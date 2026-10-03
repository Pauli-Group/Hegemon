use hegemon_standalone_pay1x2_relation_prototype::valid_fixture;
use hegemon_standalone_pay1x2_statement_prototype::{
    adapt_action, decode_exact, mutation_matrix, verify_action_statement, AdapterError,
    CanonicalCiphertextBytes, NetworkIdentity, CANONICAL_STATEMENT_BYTES, KAT_NETWORK_IDENTITY,
};

fn fixture() -> (
    hegemon_standalone_pay1x2_relation_prototype::Pay1x2Statement,
    CanonicalCiphertextBytes<'static>,
    CanonicalCiphertextBytes<'static>,
    NetworkIdentity,
) {
    let (relation, _) = valid_fixture().expect("valid relation fixture");
    let recipient =
        CanonicalCiphertextBytes::from_validated_exact(b"canonical-recipient-ciphertext-v1")
            .expect("recipient ciphertext");
    let change = CanonicalCiphertextBytes::from_validated_exact(b"canonical-change-ciphertext-v1")
        .expect("change ciphertext");
    (relation, recipient, change, KAT_NETWORK_IDENTITY)
}

#[test]
fn exact_statement_roundtrips_and_binds_action() {
    let (relation, recipient, change, network) = fixture();
    let statement = adapt_action(&relation, [recipient, change], network).expect("adapt action");
    let encoded = statement.encode();
    assert_eq!(encoded.len(), CANONICAL_STATEMENT_BYTES);
    assert_eq!(decode_exact(&encoded).expect("decode"), statement);
    assert_eq!(
        verify_action_statement(&encoded, &relation, [recipient, change], network)
            .expect("verify exact action"),
        statement
    );
    assert_eq!(statement.relation_statement(), relation);
}

#[test]
fn statement_known_answer_is_frozen() {
    let (relation, recipient, change, network) = fixture();
    let statement = adapt_action(&relation, [recipient, change], network).expect("adapt action");

    assert_eq!(
        statement.ciphertext_hashes[0].as_bytes(),
        &[
            116, 95, 94, 42, 144, 209, 224, 175, 247, 216, 77, 18, 42, 167, 233, 5, 215, 67, 243,
            116, 98, 19, 4, 115, 40, 114, 209, 0, 34, 108, 177, 7, 227, 170, 228, 222, 101, 76, 32,
            188, 137, 183, 55, 90, 57, 118, 96, 253, 136, 177, 156, 128, 191, 74, 171, 102,
        ]
    );
    assert_eq!(
        statement.ciphertext_hashes[1].as_bytes(),
        &[
            153, 113, 139, 91, 35, 74, 87, 69, 237, 219, 176, 108, 53, 1, 63, 159, 191, 62, 153,
            77, 76, 6, 52, 204, 87, 33, 167, 130, 238, 34, 39, 48, 236, 11, 30, 30, 45, 167, 249,
            230, 193, 134, 52, 108, 71, 244, 192, 16, 239, 39, 203, 153, 162, 199, 237, 243,
        ]
    );
    assert_eq!(
        statement.balance_tag.as_bytes(),
        &[
            93, 230, 221, 200, 117, 217, 3, 186, 6, 197, 102, 72, 222, 237, 35, 209, 10, 194, 93,
            253, 50, 60, 59, 233, 210, 222, 193, 87, 158, 235, 190, 249, 211, 147, 121, 216, 166,
            162, 58, 243, 241, 84, 161, 200, 63, 221, 114, 241, 29, 54, 20, 240, 171, 192, 183,
            150,
        ]
    );
    assert_eq!(
        statement.network_binding.as_bytes(),
        &[
            228, 53, 27, 26, 58, 249, 240, 180, 243, 123, 39, 248, 103, 175, 151, 71, 252, 178,
            109, 133, 58, 134, 76, 247, 236, 191, 122, 214, 52, 211, 64, 107, 122, 67, 157, 89,
            132, 205, 124, 142, 115, 42, 21, 130, 2, 0, 4, 180, 1, 127, 80, 28, 49, 93, 50, 217,
        ]
    );
    assert_eq!(
        statement.binding_digest(),
        [
            33, 28, 78, 117, 162, 85, 170, 25, 2, 18, 171, 130, 122, 147, 59, 69, 188, 194, 93,
            138, 252, 207, 233, 138, 240, 96, 143, 224, 132, 215, 30, 7, 168, 122, 40, 171, 95,
            158, 23, 52, 48, 37, 45, 40, 85, 158, 241, 156, 85, 33, 12, 168, 205, 120, 213, 91,
            100, 83, 225, 133, 216, 96, 64, 78,
        ]
    );
}

#[test]
fn exact_decoder_rejects_truncation_and_trailing_bytes() {
    let (relation, recipient, change, network) = fixture();
    let encoded = adapt_action(&relation, [recipient, change], network)
        .expect("adapt action")
        .encode();
    assert!(matches!(
        decode_exact(&encoded[..encoded.len() - 1]),
        Err(AdapterError::Truncated { .. })
    ));
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(matches!(
        decode_exact(&trailing),
        Err(AdapterError::TrailingBytes { .. })
    ));
}

#[test]
fn every_one_field_mutation_rejects() {
    let outcomes = mutation_matrix().expect("mutation matrix");
    assert_eq!(outcomes.len(), 28);
    for name in [
        "network_binding",
        "source.chain_id",
        "source.genesis",
        "source.rules_hash",
    ] {
        assert!(
            outcomes
                .iter()
                .any(|outcome| outcome.name == name && outcome.rejected),
            "missing rejecting network mutation {name}"
        );
    }
    let admitted: Vec<_> = outcomes
        .iter()
        .filter(|outcome| !outcome.rejected)
        .map(|outcome| outcome.name)
        .collect();
    assert!(admitted.is_empty(), "mutations accepted: {admitted:?}");
}

#[test]
fn ciphertext_admission_is_explicit_and_bounded() {
    assert!(matches!(
        CanonicalCiphertextBytes::from_validated_exact(&[]),
        Err(AdapterError::EmptyCiphertext)
    ));
    let oversized = vec![0u8; 1_048_577];
    assert!(matches!(
        CanonicalCiphertextBytes::from_validated_exact(&oversized),
        Err(AdapterError::CiphertextTooLarge { .. })
    ));
}

#[test]
fn fee_mutation_cannot_reuse_the_old_balance_tag() {
    let (mut relation, recipient, change, network) = fixture();
    let encoded = adapt_action(&relation, [recipient, change], network)
        .expect("adapt action")
        .encode();
    relation.fee ^= 1;
    assert!(matches!(
        verify_action_statement(&encoded, &relation, [recipient, change], network),
        Err(AdapterError::ActionFieldMismatch("fee"))
    ));
}
