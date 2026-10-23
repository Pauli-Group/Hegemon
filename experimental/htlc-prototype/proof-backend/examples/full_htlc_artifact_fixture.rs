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
pub fn fixture(action: HtlcAction, release: SecretRelease) -> (HtlcStatement, HtlcWitness) {
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

fn main() {}
