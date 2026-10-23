use super::*;
use crate::smallwood_poseidon2_v8_coinbase::{
    poseidon2_v8_note_tree_compress as merkle,
    poseidon2_v8_single_key_authorization_digest as authority,
};
use sha2::{Digest as _, Sha256};
pub(super) fn key(i: u64) -> Key {
    [i, 2, 3, 4, 5]
}
pub(super) fn note(value: u64, tag: u64, owner: Digest) -> Note {
    let mut n = Note {
        value,
        asset_id: 0,
        recipient_key: [tag; 4],
        authorization_key: [0; 4],
        rho: [tag + 20; 4],
        randomness: [0, 0, 0, tag + 90],
    };
    set_note_owner(&mut n, owner);
    n
}
fn input(value: u64, tag: u64) -> PrivateInput {
    PrivateInput {
        occupied: 1,
        legacy_ordinary: 1,
        note: note(value, tag, authority(key(tag)).unwrap()),
        spend_key: key(tag),
        ..Default::default()
    }
}
pub(super) fn tree(w: &mut PrivateSpendWitness) -> Digest {
    let leaves = w
        .inputs
        .each_ref()
        .map(|i| note_commitment(i.note).unwrap());
    let mut root = merkle(leaves[0], leaves[1]);
    for _ in 1..32 {
        root = merkle(root, [0; 7])
    }
    for i in 0..2 {
        if w.inputs[i].occupied == 1 {
            w.inputs[i].position = i as u32;
            w.inputs[i].siblings = [[0; 7]; 32];
            w.inputs[i].siblings[0] = leaves[1 - i];
        }
    }
    root
}
pub(super) fn effects(p: &mut PrivateSpendPublic, w: &PrivateSpendWitness) {
    for i in 0..2 {
        p.commitments[i] = note_commitment(w.outputs[i]).unwrap();
        p.nullifiers[i] = if w.inputs[i].occupied == 0 {
            dummy_nullifier(p.chain_id, w.inputs[i].dummy_secret).unwrap()
        } else {
            let k = if (i == 0 && (w.selectors[1] == 1 || w.selectors[2] == 1))
                || (i == 1 && w.selectors[2] == 1)
            {
                w.treasury.policy_key
            } else if i == 0 && w.policy.spend == 1 {
                w.policy.input.nullifier_key
            } else if i == 0 && (w.selectors[4] == 1 || w.selectors[5] == 1) {
                w.htlc.nullifier_key
            } else {
                w.inputs[i].spend_key
            };
            real_nullifier(k, w.inputs[i].position, w.inputs[i].note).unwrap()
        };
    }
}
pub(super) fn fixture(mode: usize) -> (PrivateSpendPublic, PrivateSpendWitness) {
    let mut p = PrivateSpendPublic {
        chain_id: [1; 32],
        reference_parent_hash: [2; 32],
        reference_parent_height: 100,
        merkle_root: [0; 7],
        fee: 10,
        nullifiers: [[0; 7]; 2],
        commitments: [[0; 7]; 2],
        ciphertext_commitments: [[3; 48], [4; 48]],
        secret_release: 0,
        released_secret: [0; 32],
    };
    let auth = [authority(key(11)).unwrap(), authority(key(12)).unwrap()];
    let mut w = PrivateSpendWitness {
        selectors: [0; 6],
        inputs: [
            input(100, 1),
            PrivateInput {
                dummy_secret: key(9),
                ..Default::default()
            },
        ],
        outputs: [
            note(90, 5, ordinary_owner(auth[0]).unwrap()),
            note(0, 6, ordinary_owner(auth[1]).unwrap()),
        ],
        output_authorities: auth,
        treasury: TreasuryOpening {
            intent: vec![0; INTENT_WORDS],
            ..Default::default()
        },
        htlc: PrivateHtlcOpening::default(),
        policy: PrivatePolicyOpening::default(),
    };
    w.selectors[mode] = 1;
    if mode == 1 || mode == 2 {
        w.treasury = TreasuryOpening {
            policy_key: key(40),
            signer_tags: [
                authority(key(21)).unwrap(),
                authority(key(22)).unwrap(),
                authority(key(23)).unwrap(),
            ],
            approved: if mode == 2 { [1, 1, 0] } else { [0; 3] },
            selected_signer: if mode == 1 { [1, 0, 0] } else { [0; 3] },
            intent: vec![0; INTENT_WORDS],
        };
        if mode == 1 {
            w.inputs = [
                PrivateInput {
                    dummy_secret: key(9),
                    ..Default::default()
                },
                input(20, 21),
            ];
            w.output_authorities[0] = [0; 7];
            w.outputs[0] = note(
                0,
                5,
                treasury_accumulator_owner(&w.treasury, [1, 0, 0]).unwrap(),
            );
            w.outputs[1].value = 10;
        } else {
            w.inputs[0] = PrivateInput {
                occupied: 1,
                note: note(100, 7, treasury_value_owner(&w.treasury).unwrap()),
                ..Default::default()
            };
            w.inputs[1] = PrivateInput {
                occupied: 1,
                note: note(0, 8, [0; 7]),
                ..Default::default()
            };
            w.inputs[1].position = 1;
            effects(&mut p, &w);
            w.treasury.intent = p.intent_words().to_vec();
            set_note_owner(
                &mut w.inputs[1].note,
                treasury_accumulator_owner(&w.treasury, [1, 1, 0]).unwrap(),
            );
        }
    }
    if mode >= 3 {
        w.htlc = PrivateHtlcOpening {
            nullifier_key: key(50),
            hashlock: Sha256::digest([42; 32]).into(),
            claim_authority: authority(key(11)).unwrap(),
            refund_authority: authority(key(12)).unwrap(),
            claim_recipient: [5; 4],
            refund_recipient: [7; 4],
            timeout: 120,
            secret: if mode == 4 { [42; 32] } else { [0; 32] },
            release_secret: 0,
        };
        w.inputs[1] = input(10, 2);
        w.outputs[0].value = 100;
        if mode == 3 {
            w.output_authorities[0] = [0; 7];
            set_note_owner(&mut w.outputs[0], htlc_owner(p.chain_id, &w.htlc).unwrap());
        } else {
            if mode == 5 {
                p.reference_parent_height = 120;
                w.outputs[0].recipient_key = w.htlc.refund_recipient;
                w.output_authorities[0] = w.htlc.refund_authority;
                set_note_owner(
                    &mut w.outputs[0],
                    ordinary_owner(w.output_authorities[0]).unwrap(),
                );
            }
            w.inputs[0] = PrivateInput {
                occupied: 1,
                note: note(100, 7, htlc_owner(p.chain_id, &w.htlc).unwrap()),
                spend_key: if mode == 4 { key(11) } else { key(12) },
                ..Default::default()
            };
        }
    }
    p.merkle_root = tree(&mut w);
    effects(&mut p, &w);
    (p, w)
}
fn rejects(a: &PrivateSpendAdapter, p: &PrivateSpendPublic, w: &PrivateSpendWitness) {
    let packed = a.lower(p, w).unwrap();
    assert!(a.verify_packed_witness(&packed).is_err());
}
#[test]
fn private_spend_all_six_static_relation_and_mutations() {
    let mut geometry = None;
    for mode in 0..6 {
        let (p, w) = fixture(mode);
        let (a, packed) = compile(&p, &w).unwrap_or_else(|e| panic!("mode {mode}: {e:?}"));
        let g = (
            a.geometry().rows,
            a.geometry().nonlinear_batches,
            a.geometry().linear_equations,
            a.geometry().private_inputs,
        );
        if geometry.is_none() { eprintln!("REPAIR_CENSUS {:?}", a.lowering_census()); eprintln!("REPAIR_GEOMETRY canonical={} rows={} nonlinear={} linear={} inputs={}", a.geometry().canonical_wires, g.0, g.1, g.2, g.3); }
        if let Some(expected) = geometry {
            assert_eq!(g, expected)
        } else {
            geometry = Some(g)
        }
        // Direct canonical-wire and copied-occurrence corruptions: bypass lower.
        let first_occurrence = a.geometry().canonical_wires.div_ceil(64) * 64;
        let mut mutation_indices = vec![
            0,
            PUBLIC_WORDS,
            a.geometry().canonical_wires - 1,
            first_occurrence,
            packed.len() - 1,
        ];
        mutation_indices.extend(a.adversarial_probe_indices());
        if a.geometry().canonical_wires < first_occurrence {
            mutation_indices.push(a.geometry().canonical_wires);
        }
        for index in mutation_indices {
            let mut corrupt = packed.clone();
            corrupt[index] = (corrupt[index] + 1) % hegemon_field::GOLDILOCKS_MODULUS;
            assert!(
                a.verify_packed_witness(&corrupt).is_err(),
                "mode {mode}, packed index {index}"
            );
        }
        let mut bad = w.clone();
        bad.selectors = [0; 6];
        rejects(&a, &p, &bad);
        let mut bad = w.clone();
        bad.selectors[(mode + 1) % 6] = 1;
        rejects(&a, &p, &bad);
        let mut bad = w.clone();
        bad.outputs[1].value += 1;
        rejects(&a, &p, &bad);
        let occupied = if mode == 1 { 1 } else { 0 };
        let mut bad = w.clone();
        bad.inputs[occupied].siblings[4][0] += 1;
        rejects(&a, &p, &bad);
        let mut changed = p.clone();
        changed.fee += 1;
        rejects(&a, &changed, &w);
        let mut changed = p.clone();
        changed.ciphertext_commitments[0][0] ^= 1;
        rejects(&a, &changed, &w);
        if mode == 0 || mode == 1 {
            let i = if mode == 0 { 1 } else { 0 };
            let mut bad = w.clone();
            bad.inputs[i].note.value = 1;
            rejects(&a, &p, &bad);
        }
        if mode == 1 {
            let mut bad = w.clone();
            bad.treasury.approved = [1, 0, 0];
            rejects(&a, &p, &bad);
            let mut bad = w.clone();
            bad.treasury.signer_tags[1] = bad.treasury.signer_tags[0];
            rejects(&a, &p, &bad);
        }
        if mode == 2 {
            let mut bad = w.clone();
            bad.treasury.intent[8] += 1;
            rejects(&a, &p, &bad);
            let mut bad = w.clone();
            bad.treasury.approved = [1, 0, 0];
            rejects(&a, &p, &bad);
        }
        if mode == 3 {
            let mut bad = w.clone();
            bad.htlc.timeout = 113;
            rejects(&a, &p, &bad);
        }
        if mode == 4 {
            let mut bad = w.clone();
            bad.htlc.secret[0] ^= 1;
            rejects(&a, &p, &bad);
            let mut bad = w.clone();
            bad.inputs[0].spend_key = key(12);
            rejects(&a, &p, &bad);
        }
        if mode == 5 {
            let mut changed = p.clone();
            changed.reference_parent_height = 119;
            let b = PrivateSpendAdapter::from_public(&changed).unwrap();
            rejects(&b, &changed, &w);
        }
    }
}
#[test]
fn private_spend_real_nullifier_not_slot_action_or_context() {
    let n = note(100, 7, [8; 7]);
    let nf = real_nullifier(key(50), 11, n).unwrap();
    assert_eq!(
        nf,
        crate::smallwood_poseidon2_v8_rp06::rp06_policy_note_nullifier(key(50), 11, n.rho).unwrap()
    );
    let (mut p, w) = fixture(4);
    let claim = p.nullifiers[0];
    p.reference_parent_height += 10;
    effects(&mut p, &w);
    assert_eq!(claim, p.nullifiers[0]);
    assert_ne!(
        dummy_nullifier([1; 32], key(8)).unwrap(),
        dummy_nullifier([1; 32], key(9)).unwrap()
    );
}

#[test]
fn private_spend_occupied_zero_accumulator_and_wrapped_respends() {
    let (mut p, mut w) = fixture(1);
    w.treasury.approved = [1, 0, 0];
    w.treasury.selected_signer = [0, 1, 0];
    w.inputs[0] = PrivateInput {
        occupied: 1,
        note: note(
            0,
            8,
            treasury_accumulator_owner(&w.treasury, [1, 0, 0]).unwrap(),
        ),
        ..Default::default()
    };
    w.inputs[1] = input(20, 22);
    set_note_owner(
        &mut w.outputs[0],
        treasury_accumulator_owner(&w.treasury, [1, 1, 0]).unwrap(),
    );
    p.merkle_root = tree(&mut w);
    effects(&mut p, &w);
    let (a, _) = compile(&p, &w).unwrap();
    let mut bad = w.clone();
    bad.inputs[0].siblings[3][0] = 1;
    rejects(&a, &p, &bad);
    let (first_public, first_witness) = fixture(0);
    compile(&first_public, &first_witness).unwrap();
    let (mut p, mut w) = fixture(0);
    w.inputs[0] = PrivateInput {
        occupied: 1,
        legacy_ordinary: 0,
        note: first_witness.outputs[0],
        spend_key: key(11),
        ..Default::default()
    };
    w.outputs[0].value = w.inputs[0].note.value - p.fee;
    p.merkle_root = tree(&mut w);
    effects(&mut p, &w);
    compile(&p, &w).unwrap();
}

#[test]
fn private_spend_two_approval_accumulator_lineage_to_final() {
    let (mut final_public, mut final_witness) = fixture(2);
    let final_intent = final_witness.treasury.intent.clone();
    let (mut first_public, mut first) = fixture(1);
    first.treasury.intent = final_intent.clone();
    set_note_owner(
        &mut first.outputs[0],
        treasury_accumulator_owner(&first.treasury, [1, 0, 0]).unwrap(),
    );
    first_public.merkle_root = tree(&mut first);
    effects(&mut first_public, &first);
    compile(&first_public, &first).unwrap();
    let (mut second_public, mut second) = fixture(1);
    second.treasury.intent = final_intent;
    second.treasury.approved = [1, 0, 0];
    second.treasury.selected_signer = [0, 1, 0];
    second.inputs[0] = PrivateInput {
        occupied: 1,
        note: first.outputs[0],
        ..Default::default()
    };
    second.inputs[1] = input(20, 22);
    set_note_owner(
        &mut second.outputs[0],
        treasury_accumulator_owner(&second.treasury, [1, 1, 0]).unwrap(),
    );
    second_public.merkle_root = tree(&mut second);
    effects(&mut second_public, &second);
    let (second_adapter, _) = compile(&second_public, &second).unwrap();
    let mut duplicate = second.clone();
    duplicate.treasury.selected_signer = [1, 0, 0];
    duplicate.inputs[1] = input(20, 21);
    rejects(&second_adapter, &second_public, &duplicate);
    final_witness.inputs[1] = PrivateInput {
        occupied: 1,
        note: second.outputs[0],
        ..Default::default()
    };
    final_public.merkle_root = tree(&mut final_witness);
    effects(&mut final_public, &final_witness);
    assert_eq!(final_witness.treasury.intent, final_public.intent_words());
    compile(&final_public, &final_witness).unwrap();
    // Replacing the fully approved opening with the first accumulator fails,
    // even when public Merkle membership is refreshed for that older note.
    final_witness.inputs[1].note = first.outputs[0];
    final_public.merkle_root = tree(&mut final_witness);
    effects(&mut final_public, &final_witness);
    assert!(compile(&final_public, &final_witness).is_err());
}

#[test]
fn private_spend_full_digest_signer_distinctness() {
    let (mut p, mut w) = fixture(1);
    // Only signer0 approves here. The other two committed full digests need
    // not have a nonzero first coordinate, nor distinct first coordinates.
    w.treasury.signer_tags[1][0] = w.treasury.signer_tags[0][0];
    w.treasury.signer_tags[2][0] = 0;
    set_note_owner(
        &mut w.outputs[0],
        treasury_accumulator_owner(&w.treasury, [1, 0, 0]).unwrap(),
    );
    p.merkle_root = tree(&mut w);
    effects(&mut p, &w);
    compile(&p, &w).unwrap();
    w.treasury.signer_tags[2] = w.treasury.signer_tags[1];
    set_note_owner(
        &mut w.outputs[0],
        treasury_accumulator_owner(&w.treasury, [1, 0, 0]).unwrap(),
    );
    effects(&mut p, &w);
    assert!(compile(&p, &w).is_err());
}
