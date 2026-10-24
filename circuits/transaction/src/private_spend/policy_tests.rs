use super::tests::{effects, fixture, key, tree};
use super::*;
use crate::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest as authority;
use sha2::{Digest as _, Sha256};

fn policy(hash: bool, release: bool) -> BoundedPolicy {
    BoundedPolicy {
        nullifier_key: key(70),
        branches: [
            PolicyBranch {
                enabled: 1,
                authority: authority(key(11)).unwrap(),
                not_before: 100,
                hash_required: u64::from(hash),
                hashlock: if hash {
                    Sha256::digest([42; 32]).into()
                } else {
                    [0; 32]
                },
                release_secret: u64::from(release),
            },
            PolicyBranch {
                enabled: 1,
                authority: authority(key(12)).unwrap(),
                not_before: 120,
                ..Default::default()
            },
        ],
    }
}
fn policy_fixture(
    create: bool,
    branch: usize,
    hash: bool,
    release: bool,
) -> (PrivateSpendPublic, PrivateSpendWitness) {
    let (mut p, mut w) = fixture(0);
    let descriptor = policy(hash, release);
    if create {
        w.policy.create = 1;
        w.policy.output = descriptor.clone();
        w.output_authorities[0] = [0; 7];
        set_note_owner(
            &mut w.outputs[0],
            policy_owner(p.chain_id, 0, &descriptor).unwrap(),
        );
    } else {
        w.policy.spend = 1;
        w.policy.input = descriptor.clone();
        w.policy.selected[branch] = 1;
        w.inputs[0].legacy_ordinary = 0;
        w.inputs[0].spend_key = key(11 + branch as u64);
        set_note_owner(
            &mut w.inputs[0].note,
            policy_owner(p.chain_id, 0, &descriptor).unwrap(),
        );
        p.reference_parent_height = descriptor.branches[branch].not_before;
        if branch == 0 && hash {
            w.policy.secret = [42; 32];
        }
        if branch == 0 && release {
            p.secret_release = 1;
            p.released_secret = [42; 32];
        }
    }
    p.merkle_root = tree(&mut w);
    effects(&mut p, &w);
    (p, w)
}
fn fails(p: &PrivateSpendPublic, w: &PrivateSpendWitness) {
    assert!(compile(p, w).is_err());
}
#[test]
fn bounded_policy_absolute_height_and_branch_authorization() {
    let (p, w) = policy_fixture(false, 0, false, false);
    compile(&p, &w).unwrap();
    let mut early = p.clone();
    early.reference_parent_height = 99;
    fails(&early, &w);
    let mut bad = w.clone();
    bad.inputs[0].spend_key = key(12);
    fails(&p, &bad);
    let mut bad = w.clone();
    bad.policy.selected = [0, 1];
    fails(&p, &bad);
    let mut bad = w.clone();
    bad.policy.selected = [1, 1];
    fails(&p, &bad);
    let mut bad = w.clone();
    bad.policy.input.branches[1].not_before = 0;
    fails(&p, &bad);
    let mut bad = w.clone();
    bad.policy.input.nullifier_key[1] += 1;
    fails(&p, &bad);
    let (recovery_p, recovery_w) = policy_fixture(false, 1, false, false);
    compile(&recovery_p, &recovery_w).unwrap();
    assert_eq!(p.nullifiers[0], recovery_p.nullifiers[0]);
    assert_eq!(w.inputs[0].note, recovery_w.inputs[0].note);
    let mut early = recovery_p.clone();
    early.reference_parent_height = 119;
    fails(&early, &recovery_w);
}
#[test]
fn bounded_policy_hash_release_is_committed_and_mandatory() {
    let (p, w) = policy_fixture(false, 0, true, true);
    compile(&p, &w).unwrap();
    let mut hidden = p.clone();
    hidden.secret_release = 0;
    hidden.released_secret = [0; 32];
    fails(&hidden, &w);
    let mut wrong = p.clone();
    wrong.released_secret[31] ^= 1;
    fails(&wrong, &w);
    let mut bad = w.clone();
    bad.policy.secret[0] ^= 1;
    fails(&p, &bad);
    let mut bad = w.clone();
    bad.policy.input.branches[0].release_secret = 0;
    fails(&p, &bad);
    let (private_p, private_w) = policy_fixture(false, 0, true, false);
    compile(&private_p, &private_w).unwrap();
    assert_eq!(private_p.secret_release, 0);
    let mut disclosure = private_p.clone();
    disclosure.secret_release = 1;
    disclosure.released_secret = [42; 32];
    fails(&disclosure, &private_w);
    let mut bad = private_w.clone();
    bad.policy.input.branches[0].hash_required = 0;
    fails(&private_p, &bad);
}
#[test]
fn bounded_policy_creation_padding_and_rollover() {
    let (p, w) = policy_fixture(true, 0, true, true);
    compile(&p, &w).unwrap();
    let mut bad = w.clone();
    bad.policy.output.branches[0].enabled = 0;
    fails(&p, &bad);
    let mut bad = w.clone();
    bad.policy.output.branches[1].enabled = 0;
    fails(&p, &bad);
    let mut bad = w.clone();
    bad.policy.output.branches[0].release_secret = 2;
    fails(&p, &bad);
    let mut bad = w.clone();
    bad.policy.output.nullifier_key[0] = 0;
    fails(&p, &bad);
    let mut bad = w.clone();
    bad.policy.output.branches[0].authority = [0; 7];
    fails(&p, &bad);
    let (mut p, mut w) = policy_fixture(false, 1, false, false);
    w.policy.create = 1;
    w.policy.output = policy(false, false);
    w.output_authorities[0] = [0; 7];
    set_note_owner(
        &mut w.outputs[0],
        policy_owner(p.chain_id, 0, &w.policy.output).unwrap(),
    );
    effects(&mut p, &w);
    compile(&p, &w).unwrap();
}
#[test]
fn releasing_htlc_preserves_private_mode_and_forces_exact_disclosure() {
    let (mut p, mut w) = fixture(4);
    let old_owner = htlc_owner(p.chain_id, &w.htlc).unwrap();
    w.htlc.release_secret = 1;
    let new_owner = htlc_owner(p.chain_id, &w.htlc).unwrap();
    assert_ne!(old_owner, new_owner);
    set_note_owner(&mut w.inputs[0].note, new_owner);
    p.merkle_root = tree(&mut w);
    effects(&mut p, &w);
    p.secret_release = 1;
    p.released_secret = [42; 32];
    compile(&p, &w).unwrap();
    let mut hidden = p.clone();
    hidden.secret_release = 0;
    hidden.released_secret = [0; 32];
    fails(&hidden, &w);
    let mut wrong = p.clone();
    wrong.released_secret[0] ^= 1;
    fails(&wrong, &w);
    let mut bad = w.clone();
    bad.htlc.release_secret = 0;
    fails(&p, &bad);
    let (private_p, private_w) = fixture(4);
    compile(&private_p, &private_w).unwrap();
    assert_eq!(private_p.secret_release, 0);
}
#[test]
#[ignore = "actual proof generation benchmark; run explicitly in optimized profile"]
fn bounded_policy_actual_proof_overhead() {
    let mut cases = vec![
        ("ordinary", fixture(0)),
        ("policy_create", policy_fixture(true, 0, true, true)),
        ("absolute_height", policy_fixture(false, 0, false, false)),
        ("policy_hash_release", policy_fixture(false, 0, true, true)),
    ];
    let (mut p, mut w) = fixture(4);
    w.htlc.release_secret = 1;
    set_note_owner(
        &mut w.inputs[0].note,
        htlc_owner(p.chain_id, &w.htlc).unwrap(),
    );
    p.merkle_root = tree(&mut w);
    effects(&mut p, &w);
    p.secret_release = 1;
    p.released_secret = [42; 32];
    cases.push(("htlc_release", (p, w)));
    for (name, (p, w)) in cases {
        let (a, _) = compile(&p, &w).unwrap();
        let hint = candidate_proof_size_hint(&p).unwrap();
        let start = std::time::Instant::now();
        let proof = prove_candidate(&p, &w).unwrap();
        let proving = start.elapsed();
        let start = std::time::Instant::now();
        verify_candidate(&p, &proof).unwrap();
        let verification = start.elapsed();
        assert_eq!(hint, proof.len());
        if p.secret_release == 1 {
            let mut wrong = p.clone();
            wrong.released_secret[0] ^= 1;
            assert!(verify_candidate(&wrong, &proof).is_err());
        }
        if let Ok(dir) = std::env::var("HEGEMON_POLICY_PROOF_DIR") {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(format!("{dir}/{name}.proof"), &proof).unwrap();
            std::fs::write(format!("{dir}/{name}.statement"), p.binding_bytes()).unwrap();
        }
        eprintln!(
            "POLICY_MEASUREMENT {}",
            serde_json::json!({"case":name,"relation_digest":hex::encode(relation_digest()),"proof_bytes":proof.len(),"carrier_bytes":568+2*2608+proof.len(),"public_words":PUBLIC_WORDS,"rows":a.geometry().rows,"canonical_wires":a.geometry().canonical_wires,"linear_equations":a.geometry().linear_equations,"nonlinear_batches":a.geometry().nonlinear_batches,"proving_seconds":proving.as_secs_f64(),"verification_seconds":verification.as_secs_f64()})
        );
    }
}
