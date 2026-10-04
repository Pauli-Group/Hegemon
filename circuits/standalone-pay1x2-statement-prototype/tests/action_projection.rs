use hegemon_standalone_pay1x2_relation_prototype::{valid_fixture, Pay1x2Statement};
use hegemon_standalone_pay1x2_statement_prototype::{
    adapt_canonical_action, verify_canonical_action_statement, ActionProjectionError, BlockId48,
    CanonicalCiphertextBytes, ChainId32, NetworkBinding56, NetworkIdentity,
    ProspectiveCandidateArtifact, ProspectiveFamilyId, ProspectivePay1x2InlineAction,
    ProspectiveStablecoinBinding, RulesHash48, CANONICAL_STATEMENT_BYTES, KAT_NETWORK_IDENTITY,
};
use hegemon_standalone_shake256_prototype::{
    MerkleRoot, NoteCommitment, Nullifier, SemanticDigest,
};

type Fixture = (
    Pay1x2Statement,
    ProspectivePay1x2InlineAction<'static>,
    [u8; CANONICAL_STATEMENT_BYTES],
);

fn fixture() -> Fixture {
    let (relation, _) = valid_fixture().expect("valid relation fixture");
    let recipient =
        CanonicalCiphertextBytes::from_validated_exact(b"canonical-recipient-ciphertext-v1")
            .expect("recipient ciphertext");
    let change = CanonicalCiphertextBytes::from_validated_exact(b"canonical-change-ciphertext-v1")
        .expect("change ciphertext");
    let action = ProspectivePay1x2InlineAction::from_relation(
        &relation,
        [recipient, change],
        KAT_NETWORK_IDENTITY,
    )
    .expect("canonical action");
    let statement = adapt_canonical_action(&action, KAT_NETWORK_IDENTITY)
        .expect("adapt canonical action")
        .encode();
    (relation, action, statement)
}

fn rejection_after(
    mutate: impl FnOnce(&mut ProspectivePay1x2InlineAction<'static>),
) -> ActionProjectionError {
    let (_, mut action, statement) = fixture();
    mutate(&mut action);
    verify_canonical_action_statement(&action, &statement, KAT_NETWORK_IDENTITY)
        .expect_err("mutation must reject")
}

#[test]
fn canonical_v5_delta_action_roundtrips_to_exact_hgs2() {
    let (relation, action, statement) = fixture();
    let decoded = verify_canonical_action_statement(&action, &statement, KAT_NETWORK_IDENTITY)
        .expect("canonical action verifies");
    assert_eq!(decoded.relation_statement(), relation);
    assert_eq!(action.ciphertexts.len(), 2);
    assert_eq!(action.ciphertext_sizes, vec![33, 30]);
    assert_eq!(action.nullifiers.len(), 1);
    assert_eq!(action.commitments.len(), 2);
    assert_eq!(
        action.balance_slot_asset_ids,
        vec![0, u64::MAX, u64::MAX, u64::MAX]
    );
    assert_eq!(action.value_balance, 0);
    assert!(action.stablecoin.is_none());
    assert!(action.candidate_artifact.is_none());
    assert_eq!(action.binding_digest, decoded.binding_digest());
}

#[test]
fn every_action_projection_invariant_fails_closed() {
    let cases: Vec<(&str, ActionProjectionError)> = vec![
        (
            "kernel.circuit",
            rejection_after(|action| action.kernel_binding.circuit ^= 1),
        ),
        (
            "kernel.crypto",
            rejection_after(|action| action.kernel_binding.crypto ^= 1),
        ),
        (
            "family",
            rejection_after(|action| action.family_id = ProspectiveFamilyId(2)),
        ),
        ("action", rejection_after(|action| action.action_id.0 ^= 1)),
        (
            "ciphertext.count.missing",
            rejection_after(|action| {
                action.ciphertexts.pop();
            }),
        ),
        (
            "ciphertext.count.extra",
            rejection_after(|action| action.ciphertexts.push(action.ciphertexts[0])),
        ),
        (
            "ciphertext_size.count",
            rejection_after(|action| {
                action.ciphertext_sizes.pop();
            }),
        ),
        (
            "ciphertext_size.value",
            rejection_after(|action| action.ciphertext_sizes[0] ^= 1),
        ),
        (
            "ciphertext.order",
            rejection_after(|action| {
                action.ciphertexts.swap(0, 1);
                action.ciphertext_sizes.swap(0, 1);
            }),
        ),
        (
            "ciphertext.bytes",
            rejection_after(|action| {
                let changed = CanonicalCiphertextBytes::from_validated_exact(
                    b"canonical-recipient-ciphertext-v2",
                )
                .expect("changed canonical bytes");
                action.ciphertexts[0] = changed;
                action.ciphertext_sizes[0] = changed.as_bytes().len() as u32;
            }),
        ),
        (
            "nullifier.count.missing",
            rejection_after(|action| action.nullifiers.clear()),
        ),
        (
            "nullifier.count.extra",
            rejection_after(|action| action.nullifiers.push(action.nullifiers[0])),
        ),
        (
            "nullifier.value",
            rejection_after(|action| {
                let mut bytes = action.nullifiers[0].into_bytes();
                bytes[0] ^= 1;
                action.nullifiers[0] = Nullifier::from_digest(SemanticDigest::from_bytes(bytes));
            }),
        ),
        (
            "commitment.count.missing",
            rejection_after(|action| {
                action.commitments.pop();
            }),
        ),
        (
            "commitment.count.extra",
            rejection_after(|action| action.commitments.push(action.commitments[0])),
        ),
        (
            "commitment.order",
            rejection_after(|action| action.commitments.swap(0, 1)),
        ),
        (
            "commitment.value",
            rejection_after(|action| {
                let mut bytes = action.commitments[0].into_bytes();
                bytes[0] ^= 1;
                action.commitments[0] =
                    NoteCommitment::from_digest(SemanticDigest::from_bytes(bytes));
            }),
        ),
        (
            "anchor",
            rejection_after(|action| {
                let mut bytes = action.anchor.into_bytes();
                bytes[0] ^= 1;
                action.anchor = MerkleRoot::from_digest(SemanticDigest::from_bytes(bytes));
            }),
        ),
        ("fee", rejection_after(|action| action.fee += 1)),
        (
            "balance.count.missing",
            rejection_after(|action| action.balance_slot_asset_ids.clear()),
        ),
        (
            "balance.count.extra",
            rejection_after(|action| action.balance_slot_asset_ids.push(u64::MAX)),
        ),
        (
            "balance.native_asset",
            rejection_after(|action| action.balance_slot_asset_ids[0] = 1),
        ),
        (
            "balance.padding_asset",
            rejection_after(|action| action.balance_slot_asset_ids[1] = 0),
        ),
        (
            "value_balance",
            rejection_after(|action| action.value_balance = 1),
        ),
        (
            "stablecoin",
            rejection_after(|action| {
                action.stablecoin = Some(ProspectiveStablecoinBinding {
                    opaque_marker: [1; 32],
                })
            }),
        ),
        (
            "candidate_artifact",
            rejection_after(|action| {
                action.candidate_artifact = Some(ProspectiveCandidateArtifact {
                    opaque_bytes: vec![1],
                })
            }),
        ),
        (
            "network_binding",
            rejection_after(|action| {
                let mut bytes = action.network_binding.into_bytes();
                bytes[0] ^= 1;
                action.network_binding = NetworkBinding56::from_bytes(bytes);
            }),
        ),
        (
            "binding_digest",
            rejection_after(|action| action.binding_digest[0] ^= 1),
        ),
    ];

    assert_eq!(cases.len(), 28);
    for (name, error) in cases {
        assert!(!error.to_string().is_empty(), "empty rejection for {name}");
    }
}

#[test]
fn expected_network_identity_is_not_wallet_selectable() {
    let (_, action, statement) = fixture();
    let mut chain = KAT_NETWORK_IDENTITY.chain_id.into_bytes();
    chain[0] ^= 1;
    let wrong_chain = NetworkIdentity {
        chain_id: ChainId32::from_bytes(chain),
        ..KAT_NETWORK_IDENTITY
    };
    assert!(verify_canonical_action_statement(&action, &statement, wrong_chain).is_err());

    let mut genesis = KAT_NETWORK_IDENTITY.genesis.into_bytes();
    genesis[0] ^= 1;
    let wrong_genesis = NetworkIdentity {
        genesis: BlockId48::from_bytes(genesis),
        ..KAT_NETWORK_IDENTITY
    };
    assert!(verify_canonical_action_statement(&action, &statement, wrong_genesis).is_err());

    let mut rules = KAT_NETWORK_IDENTITY.rules_hash.into_bytes();
    rules[0] ^= 1;
    let wrong_rules = NetworkIdentity {
        rules_hash: RulesHash48::from_bytes(rules),
        ..KAT_NETWORK_IDENTITY
    };
    assert!(verify_canonical_action_statement(&action, &statement, wrong_rules).is_err());
}

#[test]
fn supplied_hgs2_bytes_are_exact_and_binding_authoritative() {
    let (_, action, statement) = fixture();
    let mut changed = statement;
    changed[30] ^= 1;
    assert!(verify_canonical_action_statement(&action, &changed, KAT_NETWORK_IDENTITY).is_err());

    let mut trailing = statement.to_vec();
    trailing.push(0);
    assert!(verify_canonical_action_statement(&action, &trailing, KAT_NETWORK_IDENTITY).is_err());
}
