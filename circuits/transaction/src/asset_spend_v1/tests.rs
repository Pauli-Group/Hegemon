use super::*;
use crate::smallwood_semantics::SmallwoodConstraintAdapter;

#[test]
fn asset_spend_all_three_operations_and_credential_depths_compile() {
    for depth in [4, 8, 16] {
        let mut geometry = None;
        for operation in [TRANSFER, MINT, BURN] {
            let (public, witness) = fixtures::fixture(operation, depth).unwrap();
            let (adapter, packed) = compile(&public, &witness).unwrap();
            assert_eq!(public.words().len(), 134);
            adapter.verify_packed_witness(&packed).unwrap();
            let shape = (
                adapter.geometry().rows,
                adapter.geometry().nonlinear_batches,
                adapter.geometry().linear_equations,
                adapter.geometry().private_inputs,
            );
            if let Some(expected) = geometry {
                assert_eq!(shape, expected);
            } else {
                geometry = Some(shape);
            }
            assert!(candidate_proof_size_hint(&public).unwrap() <= MAX_CANDIDATE_PROOF_BYTES);
        }
    }
}

#[test]
fn asset_spend_rejects_value_creation_native_fee_substitution_and_freeze() {
    let (public, witness) = fixtures::fixture(TRANSFER, 4).unwrap();
    let mut forged = witness.clone();
    forged.outputs[0].value += 1;
    let mut statement = public.clone();
    statement.commitments[0] = crate::private_spend::note_commitment(forged.outputs[0]).unwrap();
    assert!(compile(&statement, &forged).is_err());
    let mut forged = witness.clone();
    forged.outputs[2].value += 1;
    let mut statement = public.clone();
    statement.commitments[2] = crate::private_spend::note_commitment(forged.outputs[2]).unwrap();
    assert!(compile(&statement, &forged).is_err());
    let mut statement = public.clone();
    statement.frozen = true;
    assert!(compile(&statement, &witness).is_err());
    let mut statement = public.clone();
    statement.asset_id = 0;
    assert!(compile(&statement, &witness).is_err());
    let mut forged = witness.clone();
    forged.inputs[1].note.asset_id = u64::from(public.asset_id);
    let mut statement = public.clone();
    fixtures::rebind_inputs(&mut statement, &mut forged).unwrap();
    assert!(compile(&statement, &forged).is_err());
}

#[test]
fn asset_spend_mint_requires_bound_nonzero_issuer_and_enabled_policy() {
    let (public, witness) = fixtures::fixture(MINT, 4).unwrap();
    for field in 0..7 {
        let mut forged = witness.clone();
        forged.issuer_secret[field] += 1;
        assert!(compile(&public, &forged).is_err());
    }
    let mut forged = witness.clone();
    forged.issuer_secret = [0; 7];
    assert!(compile(&public, &forged).is_err());
    let mut statement = public.clone();
    statement.mint_enabled = false;
    assert!(compile(&statement, &witness).is_err());
    let mut statement = public.clone();
    statement.magnitude += 1;
    assert!(compile(&statement, &witness).is_err());
    let mut forged = witness.clone();
    forged.inputs[0].occupied = 1;
    assert!(compile(&public, &forged).is_err());
    // Native input remains mandatory when an issuer creates the asset value.
    let mut forged = witness.clone();
    forged.inputs[1] = AssetInput::default();
    assert!(compile(&public, &forged).is_err());
}

#[test]
fn asset_spend_credentials_are_mandatory_for_input_payment_and_zero_change() {
    let (public, witness) = fixtures::fixture(TRANSFER, 4).unwrap();
    for slot in 0..3 {
        for kind in 0..3 {
            let mut forged = witness.clone();
            match kind {
                0 => forged.credentials[slot].siblings[0][0] += 1,
                1 => forged.credentials[slot].expires_at += 1,
                _ => forged.credentials[slot].index ^= 1,
            }
            assert!(
                compile(&public, &forged).is_err(),
                "credential slot{slot}/kind{kind}"
            );
        }
    }
    let mut statement = public.clone();
    statement.credential_root[0] += 1;
    assert!(compile(&statement, &witness).is_err());
    let mut statement = public.clone();
    statement.policy_version += 1;
    assert!(compile(&statement, &witness).is_err());
    let mut statement = public.clone();
    statement.parent_height = 201;
    // The authenticated input expiry is200: unchanged membership alone cannot
    // rescue the credential after its height bound has expired.
    assert!(compile(&statement, &witness).is_err());
    let mut forged = witness.clone();
    forged.outputs[0].value = 10;
    forged.outputs[1].value = 0;
    let mut statement = public.clone();
    for slot in 0..2 {
        statement.commitments[slot] =
            crate::private_spend::note_commitment(forged.outputs[slot]).unwrap();
    }
    compile(&statement, &forged).unwrap();
    forged.credentials[2].siblings[0][0] += 1;
    assert!(compile(&statement, &forged).is_err());
}

#[test]
fn asset_spend_credentials_cover_entire_reference_window() {
    for mode in [0, 1] {
        for operation in [TRANSFER, MINT, BURN] {
            let (mut public, mut witness) = if mode == 0 {
                fixtures::fixture(operation, 4).unwrap()
            } else {
                fixtures::combined_fixture(operation, 4, 0).unwrap()
            };
            let horizon = credential_validity_horizon(public.parent_height).unwrap();
            let first_active = usize::from(operation == MINT);
            for slot in first_active..3 {
                witness.credentials[slot].expires_at = horizon;
            }
            fixtures::rebind_credentials(&mut public, &mut witness).unwrap();
            compile(&public, &witness).unwrap();
            if operation == MINT {
                // The absent holder stays canonical zero, never a credential bypass
                // for either of the two mandatory asset outputs.
                assert_eq!(witness.credentials[0].expires_at, 0);
            }
            for slot in first_active..3 {
                let mut expired_public = public.clone();
                let mut expired_witness = witness.clone();
                expired_witness.credentials[slot].expires_at = horizon - 1;
                // Re-authenticate the shorter expiry: this rejection must come
                // from the horizon check, rather than a stale Merkle leaf/path.
                fixtures::rebind_credentials(&mut expired_public, &mut expired_witness).unwrap();
                assert!(
                    compile(&expired_public, &expired_witness).is_err(),
                    "H+11 credential mode{mode}/operation{operation}/slot{slot}"
                );
            }
        }
    }
}

#[test]
fn asset_spend_credential_horizon_covers_zero_change_and_later_policy_branch() {
    let (mut public, mut witness) = fixtures::fixture(TRANSFER, 4).unwrap();
    witness.outputs[0].value = 10;
    witness.outputs[1].value = 0;
    for slot in 0..2 {
        public.commitments[slot] =
            crate::private_spend::note_commitment(witness.outputs[slot]).unwrap();
    }
    let horizon = credential_validity_horizon(public.parent_height).unwrap();
    for credential in &mut witness.credentials {
        credential.expires_at = horizon;
    }
    fixtures::rebind_credentials(&mut public, &mut witness).unwrap();
    compile(&public, &witness).unwrap();
    witness.credentials[2].expires_at = horizon - 1;
    fixtures::rebind_credentials(&mut public, &mut witness).unwrap();
    assert!(compile(&public, &witness).is_err());

    let (mut public, mut witness) = fixtures::combined_fixture(TRANSFER, 4, 1).unwrap();
    let horizon = credential_validity_horizon(public.parent_height).unwrap();
    for credential in &mut witness.credentials {
        credential.expires_at = horizon;
    }
    fixtures::rebind_credentials(&mut public, &mut witness).unwrap();
    compile(&public, &witness).unwrap();
    witness.credentials[0].expires_at = horizon - 1;
    fixtures::rebind_credentials(&mut public, &mut witness).unwrap();
    assert!(compile(&public, &witness).is_err());
}

#[test]
fn asset_spend_credential_horizon_rejects_48_bit_and_u64_wrap() {
    let maximum_height = (1u64 << 48) - 1;
    assert_eq!(credential_validity_horizon(0).unwrap(), 12);
    assert_eq!(
        credential_validity_horizon(maximum_height - ASSET_REFERENCE_WINDOW).unwrap(),
        maximum_height
    );
    for height in [
        maximum_height - ASSET_REFERENCE_WINDOW + 1,
        maximum_height,
        1u64 << 48,
        u64::MAX - ASSET_REFERENCE_WINDOW + 1,
        u64::MAX,
    ] {
        assert!(credential_validity_horizon(height).is_err());
        let (mut public, witness) = fixtures::fixture(TRANSFER, 4).unwrap();
        public.parent_height = height;
        assert!(public.validate_structure().is_err());
        assert!(compile(&public, &witness).is_err());
    }
    let (mut public, mut witness) = fixtures::fixture(TRANSFER, 4).unwrap();
    public.parent_height = maximum_height - ASSET_REFERENCE_WINDOW;
    for credential in &mut witness.credentials {
        credential.expires_at = maximum_height;
    }
    fixtures::rebind_credentials(&mut public, &mut witness).unwrap();
    compile(&public, &witness).unwrap();
}

#[test]
fn asset_spend_owner_recipient_asset_and_real_nullifier_are_bound() {
    let (public, witness) = fixtures::fixture(TRANSFER, 4).unwrap();
    assert_eq!(
        public.nullifiers[0],
        crate::private_spend::real_nullifier(
            witness.inputs[0].spend_key,
            witness.inputs[0].position,
            witness.inputs[0].note
        )
        .unwrap()
    );
    for slot in 0..3 {
        let mut forged = witness.clone();
        forged.output_authorities[slot][0] += 1;
        assert!(compile(&public, &forged).is_err());
    }
    let mut forged = witness.clone();
    forged.inputs[0].legacy_ordinary = 1;
    assert!(compile(&public, &forged).is_err());
    let mut forged = witness.clone();
    forged.inputs[0].spend_key[0] += 1;
    assert!(compile(&public, &forged).is_err());
    let mut statement = public.clone();
    statement.nullifiers[0][0] += 1;
    assert!(compile(&statement, &witness).is_err());
    for slot in 0..2 {
        let mut forged = witness.clone();
        forged.outputs[slot].recipient_key[0] += 1;
        let mut statement = public.clone();
        statement.commitments[slot] =
            crate::private_spend::note_commitment(forged.outputs[slot]).unwrap();
        assert!(compile(&statement, &forged).is_err());
    }
}

#[test]
fn asset_spend_each_public_wire_and_padding_is_constrained() {
    let (public, witness) = fixtures::fixture(TRANSFER, 4).unwrap();
    let (adapter, packed) = compile(&public, &witness).unwrap();
    for index in 0..PUBLIC_WORDS {
        let mut forged = packed.clone();
        forged[index] = (forged[index] + 1) % hegemon_field::GOLDILOCKS_MODULUS;
        assert!(
            adapter.verify_packed_witness(&forged).is_err(),
            "public wire{index}"
        );
    }
    let occurrence = adapter.geometry().canonical_wires.div_ceil(64) * 64;
    let mut forged = packed.clone();
    forged[occurrence] = (forged[occurrence] + 1) % hegemon_field::GOLDILOCKS_MODULUS;
    assert!(adapter.verify_packed_witness(&forged).is_err());
    assert_eq!(adapter.packing_factor(), 64);
    assert_eq!(adapter.constraint_degree(), 2);
    assert!(!SOURCE_LOWERING_CERTIFICATE_COMPLETE);
    assert!(!PRODUCTION_AUTHORIZED);
}

#[test]
fn asset_spend_helper_membership_depth_and_public_scalar_rejections() {
    let (public, witness) = fixtures::fixture(TRANSFER, 4).unwrap();
    let c = &witness.credentials[1];
    let leaf = credential_leaf(
        public.asset_id,
        public.policy_version,
        witness.outputs[0].recipient_key,
        witness.output_authorities[0],
        c.expires_at,
    )
    .unwrap();
    assert_eq!(
        credential_root(leaf, c.index, &c.siblings).unwrap(),
        public.credential_root
    );
    assert!(credential_root(leaf, 16, &c.siblings).is_err());
    for depth in [0, 3, 5, 15, 17, 64, 255] {
        let mut invalid = public.clone();
        invalid.credential_depth = depth;
        assert!(AssetSpendAdapter::from_public(&invalid).is_err());
    }
    let mut forged = witness.clone();
    forged.credentials[1].siblings.pop();
    assert!(compile(&public, &forged).is_err());
    let mut forged = witness.clone();
    forged.outputs[0].value = 1 << 56;
    assert!(compile(&public, &forged).is_err());
    assert!(verify_candidate(&public, b"SMZD").is_err());
    assert!(verify_candidate(&public, b"SMZE").is_err());
    assert!(proof_wire_receipt(b"SMZD").is_err());
}

#[test]
fn asset_spend_combined_graph_reuses_policy_for_all_operations() {
    for operation in [TRANSFER, MINT, BURN] {
        let (public, witness) = fixtures::combined_fixture(operation, 4, 0).unwrap();
        compile(&public, &witness).unwrap();
        assert_eq!(public.policy_mode, 1);
        assert_eq!(public.secret_release, u64::from(operation != MINT));
    }
    let (ordinary, witness) = fixtures::fixture(TRANSFER, 4).unwrap();
    let (ordinary_adapter, _) = compile(&ordinary, &witness).unwrap();
    let mut combined = ordinary.clone();
    combined.policy_mode = 1;
    let (combined_adapter, _) = compile(&combined, &witness).unwrap();
    assert!(combined_adapter.geometry().rows > ordinary_adapter.geometry().rows);
    let mut invalid = ordinary.clone();
    invalid.policy_mode = 2;
    assert!(compile(&invalid, &witness).is_err());
    let (_, scripted) = fixtures::combined_fixture(TRANSFER, 4, 0).unwrap();
    assert!(compile(&ordinary, &scripted).is_err());
}

#[test]
fn asset_spend_policy_height_authority_and_release_are_mandatory() {
    let (public, witness) = fixtures::combined_fixture(TRANSFER, 4, 0).unwrap();
    let mut early = public.clone();
    early.parent_height = 99;
    assert!(compile(&early, &witness).is_err());
    let mut forged = witness.clone();
    forged.inputs[0].spend_key = [16, 17, 18, 19, 20];
    assert!(compile(&public, &forged).is_err());
    let mut forged = witness.clone();
    forged.policy.selected = [0, 1];
    assert!(compile(&public, &forged).is_err());
    let mut forged = witness.clone();
    forged.policy.selected = [1, 1];
    assert!(compile(&public, &forged).is_err());
    let mut forged = witness.clone();
    forged.policy.secret[31] ^= 1;
    assert!(compile(&public, &forged).is_err());
    let mut hidden = public.clone();
    hidden.secret_release = 0;
    hidden.released_secret = [0; 32];
    assert!(compile(&hidden, &witness).is_err());
    let mut wrong = public.clone();
    wrong.released_secret[0] ^= 1;
    assert!(compile(&wrong, &witness).is_err());
    let mut forged = witness.clone();
    forged.policy.input.branches[0].release_secret = 0;
    assert!(compile(&public, &forged).is_err());
    let mut forged = witness.clone();
    forged.policy.input.branches[0].hash_required = 0;
    forged.policy.input.branches[0].hashlock = [0; 32];
    assert!(compile(&public, &forged).is_err());
}

#[test]
fn asset_spend_recovery_shares_nullifier_and_cannot_bypass_current_policy() {
    let (holder_public, holder) = fixtures::combined_fixture(TRANSFER, 4, 0).unwrap();
    let (public, witness) = fixtures::combined_fixture(TRANSFER, 4, 1).unwrap();
    compile(&public, &witness).unwrap();
    assert_eq!(holder.inputs[0].note, witness.inputs[0].note);
    assert_eq!(holder_public.nullifiers[0], public.nullifiers[0]);
    assert_eq!(
        public.nullifiers[0],
        crate::private_spend::real_nullifier(
            witness.policy.input.nullifier_key,
            witness.inputs[0].position,
            witness.inputs[0].note,
        )
        .unwrap()
    );
    let mut early = public.clone();
    early.parent_height = 119;
    assert!(compile(&early, &witness).is_err());
    let mut frozen = public.clone();
    frozen.frozen = true;
    assert!(compile(&frozen, &witness).is_err());
    let mut expired = public.clone();
    expired.parent_height = 201;
    assert!(compile(&expired, &witness).is_err());
    for slot in 0..3 {
        let mut forged = witness.clone();
        forged.credentials[slot].siblings[0][0] ^= 1;
        assert!(
            compile(&public, &forged).is_err(),
            "recovery credential{slot}"
        );
    }
    let mut forged = witness.clone();
    forged.policy.input.nullifier_key[1] += 1;
    assert!(compile(&public, &forged).is_err());
    let mut forged = witness.clone();
    forged.policy.input.branches[1].authority[0] += 1;
    assert!(compile(&public, &forged).is_err());
    let mut wrong = public.clone();
    wrong.secret_release = 1;
    wrong.released_secret = [42; 32];
    assert!(compile(&wrong, &witness).is_err());
}

#[test]
fn asset_spend_policy_credentials_bind_full_owner_and_zero_change() {
    let (public, witness) = fixtures::combined_fixture(TRANSFER, 4, 0).unwrap();
    let committed_owner = crate::private_spend::policy_owner(
        public.chain_id,
        u64::from(public.asset_id),
        &witness.policy.input,
    )
    .unwrap();
    let credential = &witness.credentials[0];
    let leaf = credential_leaf(
        public.asset_id,
        public.policy_version,
        witness.inputs[0].note.recipient_key,
        committed_owner,
        credential.expires_at,
    )
    .unwrap();
    assert_eq!(
        credential_root(leaf, credential.index, &credential.siblings).unwrap(),
        public.credential_root
    );
    let authority =
        crate::smallwood_poseidon2_v8_coinbase::poseidon2_v8_single_key_authorization_digest(
            witness.inputs[0].spend_key,
        )
        .unwrap();
    let wrong_leaf = credential_leaf(
        public.asset_id,
        public.policy_version,
        witness.inputs[0].note.recipient_key,
        authority,
        credential.expires_at,
    )
    .unwrap();
    assert_ne!(
        credential_root(wrong_leaf, credential.index, &credential.siblings).unwrap(),
        public.credential_root
    );
    let mut forged = witness.clone();
    forged.outputs[0].value = 10;
    forged.outputs[1].value = 0;
    let mut statement = public.clone();
    for slot in 0..2 {
        statement.commitments[slot] =
            crate::private_spend::note_commitment(forged.outputs[slot]).unwrap();
    }
    compile(&statement, &forged).unwrap();
    forged.credentials[2].siblings[0][0] ^= 1;
    assert!(compile(&statement, &forged).is_err());
    let mut forged = witness.clone();
    forged.output_authorities[0][0] = 1;
    assert!(compile(&public, &forged).is_err());
    let mut forged = witness.clone();
    forged.outputs[2].value += 1;
    let mut statement = public.clone();
    statement.commitments[2] = crate::private_spend::note_commitment(forged.outputs[2]).unwrap();
    assert!(compile(&statement, &forged).is_err());
}
