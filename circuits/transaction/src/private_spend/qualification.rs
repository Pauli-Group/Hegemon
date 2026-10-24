//! Feature-gated disposable qualification fixtures; never production authority.
//! Keys are deliberately public constants. Do not serialize witness values.
use super::*;
use crate::smallwood_poseidon2_v8_coinbase::{
    poseidon2_v8_note_tree_compress as merkle,
    poseidon2_v8_single_key_authorization_digest as authority,
};
use sha2::{Digest as _, Sha256};
fn key(i: u64) -> Key {
    [i, 2, 3, 4, 5]
}
fn note(value: u64, tag: u64, owner: Digest) -> Note {
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
fn tree(w: &mut PrivateSpendWitness) -> Digest {
    let defaults = crate::smallwood_poseidon2_v8_coinbase::poseidon2_v8_default_note_nodes();
    let leaves = w.inputs.each_ref().map(|i| {
        if i.occupied == 1 {
            note_commitment(i.note).unwrap()
        } else {
            defaults[0]
        }
    });
    let mut root = merkle(leaves[0], leaves[1]);
    for level in 1..32 {
        root = merkle(root, defaults[level])
    }
    for i in 0..2 {
        if w.inputs[i].occupied == 1 {
            w.inputs[i].position = i as u32;
            w.inputs[i].siblings = core::array::from_fn(|level| defaults[level]);
            w.inputs[i].siblings[0] = leaves[1 - i];
        }
    }
    root
}
fn effects(p: &mut PrivateSpendPublic, w: &PrivateSpendWitness) {
    for i in 0..2 {
        p.commitments[i] = note_commitment(w.outputs[i]).unwrap();
        p.nullifiers[i] = if w.inputs[i].occupied == 0 {
            dummy_nullifier(p.chain_id, w.inputs[i].dummy_secret).unwrap()
        } else {
            let k = if (i == 0 && (w.selectors[1] == 1 || w.selectors[2] == 1))
                || (i == 1 && w.selectors[2] == 1)
            {
                w.treasury.policy_key
            } else if i == 0 && (w.selectors[4] == 1 || w.selectors[5] == 1) {
                w.htlc.nullifier_key
            } else {
                w.inputs[i].spend_key
            };
            real_nullifier(k, w.inputs[i].position, w.inputs[i].note).unwrap()
        };
    }
}
pub fn fixture(mode: usize) -> (PrivateSpendPublic, PrivateSpendWitness) {
    assert!(mode < 6, "six fixed qualification branches");
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

/// Refresh canonical fixture membership after changing an authorization owner.
pub fn refresh_fixture(p: &mut PrivateSpendPublic, w: &mut PrivateSpendWitness) {
    p.merkle_root = tree(w);
    effects(p, w);
}
/// Ciphertexts are generated before the final intent, since the latter binds
/// ciphertext hashes. The accumulator is an input; changing its owner only
/// changes membership/root and its excluded nullifier, never output AAD.
pub fn bind_fixture_ciphertexts(
    mode: usize,
    p: &mut PrivateSpendPublic,
    w: &mut PrivateSpendWitness,
    bindings: [[u8; 48]; 2],
) {
    p.ciphertext_commitments = bindings;
    if mode == 2 {
        w.treasury.intent = p.intent_words().to_vec();
        let owner = treasury_accumulator_owner(&w.treasury, w.treasury.approved).unwrap();
        set_note_owner(&mut w.inputs[1].note, owner);
    }
    refresh_fixture(p, w);
}

/// Inspect actual source-built CSR. Normalize only the final86 public target
/// rows after checking their exact (wire=i, coefficient=1) structure.
pub fn geometry_receipt(
    p: &PrivateSpendPublic,
    a: &PrivateSpendAdapter,
) -> Result<serde_json::Value, crate::TransactionCircuitError> {
    use crate::smallwood_semantics::SmallwoodConstraintAdapter;
    use serde_json::json;
    use sha2::{Digest as _, Sha512};
    let g = a.geometry();
    let offsets = a.linear_constraint_offsets();
    let indices = a.linear_constraint_indices();
    let coefficients = a.linear_constraint_coefficients();
    let targets = a.linear_targets();
    let prefix = targets
        .len()
        .checked_sub(PUBLIC_WORDS)
        .ok_or_else(|| error("qualification public CSR suffix missing"))?;
    for (i, value) in p.words().into_iter().enumerate() {
        let begin = offsets[prefix + i] as usize;
        let end = offsets[prefix + i + 1] as usize;
        if end != begin + 1
            || indices.get(begin) != Some(&(i as u32))
            || coefficients.get(begin) != Some(&1)
            || targets[prefix + i] != value
        {
            return Err(error(
                "qualification public CSR suffix differs from fixed input binding",
            ));
        }
    }
    let mut h = Sha512::new();
    h.update(b"PrivateSpendNormalizedCSR-v1");
    for x in [
        g.rows,
        g.canonical_wires,
        g.nonlinear_batches,
        g.linear_equations,
        g.private_inputs,
        g.packing,
        g.degree,
    ] {
        h.update((x as u64).to_le_bytes());
    }
    for values in [offsets, indices] {
        h.update((values.len() as u64).to_le_bytes());
        for x in values {
            h.update(x.to_le_bytes());
        }
    }
    h.update((coefficients.len() as u64).to_le_bytes());
    for x in coefficients {
        h.update(x.to_le_bytes());
    }
    h.update((targets.len() as u64).to_le_bytes());
    for (i, x) in targets.iter().enumerate() {
        h.update((if i < prefix { *x } else { 0 }).to_le_bytes());
    }
    let profile = crate::smallwood_engine::NATIVE_PRIVATE_SPEND_SMZD_SMALLWOOD_NO_GRINDING_PROFILE;
    let engine = crate::smallwood_engine::derive_smallwood_core_geometry_v1(a, profile)?;
    if engine.row_count != g.rows
        || engine.packing_factor != g.packing
        || engine.constraint_degree != g.degree
        || engine.linear_constraint_count != g.linear_equations
    {
        return Err(error("qualification geometry differs from engine-derived source shape"));
    }
    let rows = engine.row_count;
    Ok(
        json!({"canonical_wires":g.canonical_wires,"rows":rows,"nonlinear_batches":g.nonlinear_batches,
        "linear_equations":g.linear_equations,"csr_nonzero_entries":indices.len(),"input_words_including_public":g.private_inputs,
        "private_witness_input_words":g.private_inputs-PUBLIC_WORDS,"packing":g.packing,"constraint_degree":g.degree,
        "public_binding_rows":PUBLIC_WORDS,"normalized_csr_sha512":hex::encode(h.finalize()),
        "normalization":"Only exact final86 public-input RHS targets replaced by zero; all other targets retained",
        "nonlinear_constraints":engine.nonlinear_constraint_count,
        "engine_config":{"witness_degree":engine.witness_poly_degree,
          "mpol_degree":engine.mpol_poly_degree,"mlin_degree":engine.mlin_poly_degree,
          "polys":engine.nb_polys,"lvcs_rows":engine.nb_lvcs_rows,
          "lvcs_opened":engine.nb_lvcs_opened_combi,"lvcs_cols":engine.nb_lvcs_cols,
          "unstacked_rows":engine.nb_unstacked_rows,"unstacked_cols":engine.nb_unstacked_cols,
          "interpolation_points":engine.interpolation_point_count,
          "coset_shift":engine.coset_shift,"coset_generator":engine.coset_generator,
          "auxiliary_words":engine.auxiliary_word_count},
        "matrix_dimensions":[
          [engine.ppol_high_rows,engine.ppol_high_cols],
          [engine.plin_high_rows,engine.plin_high_cols],
          [engine.rcombi_rows,engine.rcombi_cols],
          [engine.subset_rows,engine.subset_cols],
          [engine.partial_rows,engine.partial_cols],
          [engine.masking_rows,engine.masking_cols],
          [engine.high_rows,engine.high_cols],
          [engine.opened_witness_rows,engine.opened_witness_cols]],
        "profile":{"rho":profile.rho,"opened_evals":profile.nb_opened_evals,
          "beta":profile.beta,"decs_domain":profile.decs_nb_evals,
          "decs_queries":profile.decs_nb_opened_evals,"eta":profile.decs_eta,
          "query_bound_qualified":false},
        "projected_inner_bytes":crate::smallwood_engine::projected_native_private_spend_smzd_inner_proof_bytes(a)?}),
    )
}
