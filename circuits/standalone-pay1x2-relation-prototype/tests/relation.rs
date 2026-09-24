use hegemon_standalone_pay1x2_relation_prototype::{
    derive_statement_unchecked, mutation_matrix, valid_fixture, verify_relation, RelationError,
    MAX_NOTE_VALUE,
};

#[test]
fn valid_native_pay1x2_accepts_with_exact_geometry() {
    assert_eq!(
        hegemon_standalone_shake256_prototype::PROFILE_TAG,
        *b"HEG-S4V2"
    );
    let (statement, witness) = valid_fixture().expect("build valid fixture");
    let stats = verify_relation(&statement, &witness).expect("valid fixture must accept");
    assert_eq!(stats.private_witness_bytes, 2_448);
    assert_eq!(stats.public_statement_bytes, 232);
    assert_eq!(stats.semantic_invocations, 37);
    assert_eq!(stats.absorbed_bytes, 5_153);
    assert_eq!(stats.merkle_parent_invocations, 32);
    assert_eq!(stats.keccak_f_permutations, 40);
    assert_eq!(stats.keccak_boolean_and_floor, 40 * 38_400);
    assert_eq!(stats.range_checks, 4);
    assert!(stats.balance_tag_external_derived);
    assert!(!stats.canonical_action_adapter_complete);
}

#[test]
fn every_named_adversarial_mutation_rejects() {
    let outcomes = mutation_matrix().expect("run mutation matrix");
    assert_eq!(outcomes.len(), 30);
    let admitted: Vec<_> = outcomes
        .iter()
        .filter(|outcome| !outcome.rejected)
        .map(|outcome| outcome.name)
        .collect();
    assert!(
        admitted.is_empty(),
        "counterfeit mutations accepted: {admitted:?}"
    );
}

#[test]
fn recomputed_hashes_do_not_rescue_semantically_invalid_witnesses() {
    let (_, base) = valid_fixture().expect("build valid fixture");

    let mut wrong_balance = base.clone();
    wrong_balance.outputs[0].value += 1;
    let statement = derive_statement_unchecked(&wrong_balance, 3).expect("derive statement");
    assert!(matches!(
        verify_relation(&statement, &wrong_balance),
        Err(RelationError::BalanceMismatch { .. })
    ));

    let mut wrong_auth = base.clone();
    wrong_auth.input.note.pk_auth[0] ^= 1;
    let statement = derive_statement_unchecked(&wrong_auth, 3).expect("derive statement");
    assert!(matches!(
        verify_relation(&statement, &wrong_auth),
        Err(RelationError::SpendAuthorizationMismatch)
    ));

    let mut rotated_change = base.clone();
    rotated_change.outputs[1].pk_recipient[0] ^= 1;
    let statement = derive_statement_unchecked(&rotated_change, 3).expect("derive statement");
    verify_relation(&statement, &rotated_change)
        .expect("fresh change diversifier remains owned through derived pk_auth");

    let mut wrong_asset = base;
    wrong_asset.outputs[0].asset_id = 1;
    let statement = derive_statement_unchecked(&wrong_asset, 3).expect("derive statement");
    assert!(matches!(
        verify_relation(&statement, &wrong_asset),
        Err(RelationError::NonNativeAsset { .. })
    ));
}

#[test]
fn range_and_position_edges_fail_closed() {
    let (statement, base) = valid_fixture().expect("build valid fixture");
    assert_eq!(MAX_NOTE_VALUE, (1u64 << 61) - 1);
    let mut value = base.clone();
    value.input.note.value = MAX_NOTE_VALUE + 1;
    assert!(matches!(
        verify_relation(&statement, &value),
        Err(RelationError::ValueOutOfRange { .. })
    ));

    let mut position = base;
    position.input.position = 1u64 << 32;
    assert!(matches!(
        verify_relation(&statement, &position),
        Err(RelationError::PositionOutOfRange(_))
    ));
}

#[test]
fn active_note_semantics_do_not_invent_zero_byte_rejections() {
    let (_, mut witness) = valid_fixture().expect("build valid fixture");
    witness.input.note.pk_recipient = [0; 32];
    witness.input.note.rho = [0; 48];
    witness.input.note.randomness = [0; 48];
    witness.outputs[0].pk_recipient = [0; 32];
    witness.outputs[0].rho = [0; 48];
    witness.outputs[0].randomness = [0; 48];
    witness.outputs[0].pk_auth = [0; 56];
    witness.outputs[1].pk_recipient = [0; 32];
    witness.outputs[1].rho = [0; 48];
    witness.outputs[1].randomness = [0; 48];

    let statement = derive_statement_unchecked(&witness, 3).expect("derive zero-field statement");
    verify_relation(&statement, &witness)
        .expect("active note validity does not reject opaque all-zero note fields");
}

#[test]
fn zero_nullifier_is_reserved_for_padding() {
    use hegemon_standalone_shake256_prototype::{Nullifier, SemanticDigest};

    let (mut statement, witness) = valid_fixture().expect("build valid fixture");
    statement.nullifier = Nullifier::from_digest(SemanticDigest::ZERO);
    assert!(matches!(
        verify_relation(&statement, &witness),
        Err(RelationError::ZeroNullifier)
    ));
}

#[test]
fn zero_output_commitments_are_reserved_for_padding() {
    use hegemon_standalone_shake256_prototype::{NoteCommitment, SemanticDigest};

    let (statement, witness) = valid_fixture().expect("build valid fixture");
    for (index, field) in [(0, "recipient output"), (1, "change output")] {
        let mut mutated = statement.clone();
        mutated.output_commitments[index] = NoteCommitment::from_digest(SemanticDigest::ZERO);
        assert!(matches!(
            verify_relation(&mutated, &witness),
            Err(RelationError::ZeroCommitment { field: actual }) if actual == field
        ));
    }
}
