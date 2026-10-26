use hegemon_isolated_htlc_smallwood::{
    smallwood_htlc::{self, HtlcAction, HtlcPolicy, HtlcStatement, HtlcWitness, SecretRelease},
    smallwood_poseidon2_v8_coinbase::{
        poseidon2_v8_empty_note_opening, poseidon2_v8_note_commitment,
        poseidon2_v8_single_key_authorization_digest, poseidon2_v8_two_note_frontier,
    },
    smallwood_poseidon2_v8_types::SmallwoodPoseidon2V8NoteOpening as Note,
};
use sha2::{Digest, Sha256};

fn note(key: [u64; 5], value: u64, recipient: [u64; 4], rho: u64) -> Note {
    let owner = poseidon2_v8_single_key_authorization_digest(key).unwrap();
    Note {
        value,
        asset_id: 0,
        recipient_key: recipient,
        authorization_key: owner[..4].try_into().unwrap(),
        rho: [rho, 0, 0, 0],
        randomness: [owner[4], owner[5], owner[6], rho + 1],
    }
}
fn fixture(action: HtlcAction, release: SecretRelease) -> (HtlcStatement, HtlcWitness) {
    let source = [11, 12, 13, 14, 15];
    let claim = [21, 22, 23, 24, 25];
    let refund = [31, 32, 33, 34, 35];
    let nk = [41, 42, 43, 44, 45];
    let secret = [71; 32];
    let policy = HtlcPolicy {
        version: 1,
        network_id: [2; 32],
        hashlock: Sha256::digest(secret).into(),
        claim_authority: poseidon2_v8_single_key_authorization_digest(claim).unwrap(),
        refund_authority: poseidon2_v8_single_key_authorization_digest(refund).unwrap(),
        claim_recipient: [51, 52, 53, 54],
        refund_recipient: [61, 62, 63, 64],
        timeout_height: 100,
        secret_release: release,
    };
    let locked =
        smallwood_htlc::bind_locked_note(note(source, 99, [81, 82, 83, 84], 91), policy, nk)
            .unwrap();
    let (input, output, spend, nullkey, preimage, height) = match action {
        HtlcAction::Lock => (
            note(source, 100, [101, 102, 103, 104], 111),
            locked,
            source,
            source,
            [0; 32],
            90,
        ),
        HtlcAction::Claim => (
            locked,
            note(claim, 98, policy.claim_recipient, 121),
            claim,
            nk,
            secret,
            90,
        ),
        HtlcAction::Refund => (
            locked,
            note(refund, 98, policy.refund_recipient, 131),
            refund,
            nk,
            [0; 32],
            100,
        ),
    };
    let commitment = poseidon2_v8_note_commitment(input).unwrap();
    let frontier = poseidon2_v8_two_note_frontier([
        commitment,
        poseidon2_v8_note_commitment(poseidon2_v8_empty_note_opening()).unwrap(),
    ])
    .unwrap();
    let statement = HtlcStatement {
        version: 1,
        action,
        network_id: [2; 32],
        parent_hash: [3; 32],
        parent_height: height,
        merkle_root: frontier.root,
        nullifier: smallwood_htlc::htlc_nullifier(nullkey, 0, input).unwrap(),
        output_commitment: poseidon2_v8_note_commitment(output).unwrap(),
        ciphertext_commitment: [4; 48],
        fee: 1,
        revealed_secret: if action == HtlcAction::Claim && release == SecretRelease::PublicOnHegemon
        {
            Some(secret)
        } else {
            None
        },
    };
    (
        statement,
        HtlcWitness {
            policy,
            policy_nullifier_key: nk,
            input_note: input,
            input_position: 0,
            input_siblings: frontier.paths[0],
            spend_key: spend,
            secret: preimage,
            output_note: output,
        },
    )
}
#[test]
fn complete_lock_claim_refund_and_same_nullifier() {
    for action in [HtlcAction::Lock, HtlcAction::Claim, HtlcAction::Refund] {
        let (s, w) = fixture(action, SecretRelease::HiddenOnHegemon);
        let (adapter, packed) = smallwood_htlc::compile(&s, &w).unwrap();
        adapter.verify_packed_witness(&packed).unwrap();
        println!("{action:?}: {:?}", adapter.geometry());
        assert_eq!(adapter.geometry().degree, 2);
    }
    let (claim, _) = fixture(HtlcAction::Claim, SecretRelease::HiddenOnHegemon);
    let (refund, _) = fixture(HtlcAction::Refund, SecretRelease::HiddenOnHegemon);
    assert_eq!(claim.nullifier, refund.nullifier);
}
#[test]
fn policy_authority_payout_secret_and_network_constraints() {
    for limb in 0..7 {
        let (s, mut w) = fixture(HtlcAction::Claim, SecretRelease::HiddenOnHegemon);
        w.policy.claim_authority[limb] += 1;
        assert!(smallwood_htlc::compile(&s, &w).is_err());
    }
    for edit in 0..10 {
        let (mut s, mut w) = fixture(HtlcAction::Claim, SecretRelease::HiddenOnHegemon);
        match edit {
            0 => w.secret[0] ^= 1,
            1 => w.policy.network_id[0] ^= 1,
            2 => w.policy.hashlock[0] ^= 1,
            3 => w.spend_key[4] += 1,
            4 => w.policy_nullifier_key[4] += 1,
            5 => w.output_note.recipient_key[3] += 1,
            6 => w.output_note.randomness[2] += 1,
            7 => w.output_note.value += 1,
            8 => s.fee += 1,
            _ => w.input_position = 1,
        };
        assert!(smallwood_htlc::compile(&s, &w).is_err(), "mutation {edit}");
    }
}
#[test]
fn maturity_secret_release_and_context_are_explicit() {
    let (mut s, w) = fixture(HtlcAction::Refund, SecretRelease::HiddenOnHegemon);
    s.parent_height = 99;
    assert!(smallwood_htlc::compile(&s, &w).is_err());
    s.parent_height = 100;
    smallwood_htlc::compile(&s, &w).unwrap();
    let (mut s, w) = fixture(HtlcAction::Claim, SecretRelease::HiddenOnHegemon);
    s.parent_height = 101;
    smallwood_htlc::compile(&s, &w).unwrap();
    s.revealed_secret = Some(w.secret);
    assert!(smallwood_htlc::compile(&s, &w).is_err());
    let (mut s, w) = fixture(HtlcAction::Claim, SecretRelease::PublicOnHegemon);
    smallwood_htlc::compile(&s, &w).unwrap();
    s.revealed_secret = None;
    assert!(smallwood_htlc::compile(&s, &w).is_err());
    assert!(s
        .validate_context([9; 32], s.parent_hash, s.parent_height, s.merkle_root)
        .is_err());
    assert!(s
        .validate_context(s.network_id, [9; 32], s.parent_height, s.merkle_root)
        .is_err());
    let (mut s, w) = fixture(HtlcAction::Lock, SecretRelease::HiddenOnHegemon);
    s.parent_height = 100;
    assert!(smallwood_htlc::compile(&s, &w).is_err());
}
#[test]
fn packed_occurrence_mutations_reject() {
    let (s, w) = fixture(HtlcAction::Refund, SecretRelease::HiddenOnHegemon);
    let (adapter, packed) = smallwood_htlc::compile(&s, &w).unwrap();
    let first = adapter.geometry().canonical_wires.div_ceil(64) * 64;
    for i in [
        0,
        first,
        first + 1,
        first + 63,
        first + 64,
        packed.len() - 1,
    ] {
        let mut changed = packed.clone();
        changed[i] ^= 1;
        assert!(adapter.verify_packed_witness(&changed).is_err());
    }
}

#[test]
fn strict_candidate_statement_binds_every_public_component() {
    let (statement, _) = fixture(HtlcAction::Claim, SecretRelease::PublicOnHegemon);
    let binding = statement.candidate_binding_bytes().unwrap();
    assert_eq!(binding.len(), smallwood_htlc::CANDIDATE_PREAMBLE_BYTES);
    assert_eq!(&binding[..8], &smallwood_htlc::CANDIDATE_PREAMBLE_MAGIC);
    for component in 0..10 {
        let mut changed = statement.clone();
        match component {
            0 => changed.network_id[31] ^= 1,
            1 => changed.parent_hash[31] ^= 1,
            2 => changed.parent_height += 1,
            3 => changed.merkle_root[6] ^= 1,
            4 => changed.nullifier[6] ^= 1,
            5 => changed.output_commitment[6] ^= 1,
            6 => changed.ciphertext_commitment[47] ^= 1,
            7 => changed.fee += 1,
            8 => changed.revealed_secret.as_mut().unwrap()[31] ^= 1,
            _ => changed.revealed_secret = None,
        }
        assert_ne!(binding, changed.candidate_binding_bytes().unwrap());
    }
    for action in [HtlcAction::Lock, HtlcAction::Refund] {
        let (changed, _) = fixture(action, SecretRelease::HiddenOnHegemon);
        assert_ne!(binding, changed.candidate_binding_bytes().unwrap());
    }
    assert!(smallwood_htlc::verify_candidate(&statement, b"SMZ1").is_err());
    assert!(smallwood_htlc::verify_candidate(&statement, b"SMZA").is_err());
}
