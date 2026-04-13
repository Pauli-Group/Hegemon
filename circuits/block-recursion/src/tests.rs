use std::sync::OnceLock;

use protocol_versioning::SMALLWOOD_CANDIDATE_VERSION_BINDING;
use super::{
    deserialize_recursive_block_artifact_v1, prove_block_recursive_v1, public_replay_v1,
    serialize_recursive_block_artifact_v1, serialize_recursive_block_public_v1,
    verify_block_recursive_v1, BaseARelationV1,
    BlockLeafRecordV1, BlockRecursionError, RecursivePrefixStatementV1,
    BlockRecursiveProverInputV1, BlockSemanticInputsV1, RecursiveBlockArtifactV1,
    RecursiveBlockPublicV1, StepARelationV1, StepBRelationV1,
    HostedRecursiveProofContextV1, hosted_base_binding_bytes_v1,
    hosted_recursive_descriptor_v1, hosted_step_binding_bytes_v1,
    verify_hosted_recursive_proof_context_components_v1,
    verify_recursive_proof_envelope_components_v1,
};
use transaction_circuit::{
    encode_smallwood_recursive_proof_envelope_v1,
    prove_recursive_statement_v1, recursive_profile_a_v1,
    recursive_profile_b_v1, verify_recursive_statement_v1, SmallwoodRecursiveProofEnvelopeV1,
    SmallwoodRecursiveProfileTagV1, SmallwoodRecursiveRelationKindV1,
    TransactionCircuitError,
};

fn digest32(tag: u8, idx: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (offset, byte) in out.iter_mut().enumerate() {
        *byte = tag
            .wrapping_add(idx as u8)
            .wrapping_add((offset as u8).wrapping_mul(3));
    }
    out
}

fn digest48(tag: u8, idx: u32) -> [u8; 48] {
    let mut out = [0u8; 48];
    for (offset, byte) in out.iter_mut().enumerate() {
        *byte = tag
            .wrapping_add(idx as u8)
            .wrapping_add((offset as u8).wrapping_mul(5));
    }
    out
}

fn sample_input(tx_count: u32) -> BlockRecursiveProverInputV1 {
    let records = (0..tx_count)
        .map(|tx_index| BlockLeafRecordV1 {
            tx_index,
            receipt_statement_hash: digest48(0x10, tx_index),
            receipt_proof_digest: digest48(0x20, tx_index),
            receipt_public_inputs_digest: digest48(0x30, tx_index),
            receipt_verifier_profile: digest48(0x40, tx_index),
            leaf_params_fingerprint: digest48(0x50, tx_index),
            leaf_spec_digest: digest32(0x60, tx_index),
            leaf_relation_id: digest32(0x70, tx_index),
            leaf_shape_digest: digest32(0x80, tx_index),
            leaf_statement_digest: digest48(0x90, tx_index),
            leaf_commitment_digest: digest48(0xa0, tx_index),
            leaf_proof_digest: digest48(0xb0, tx_index),
        })
        .collect();
    BlockRecursiveProverInputV1 {
        records,
        semantic: BlockSemanticInputsV1 {
            tx_statements_commitment: digest48(0xc0, tx_count),
            start_shielded_root: digest48(0xd0, 0),
            end_shielded_root: digest48(0xd1, tx_count),
            start_kernel_root: digest48(0xe0, 0),
            end_kernel_root: digest48(0xe1, tx_count),
            nullifier_root: digest48(0xf0, tx_count),
            da_root: digest48(0xf8, tx_count),
            start_tree_commitment: digest48(0xa8, 0),
            end_tree_commitment: digest48(0xa9, tx_count),
        },
    }
}

fn prove_artifact(tx_count: u32) -> (RecursiveBlockArtifactV1, RecursiveBlockPublicV1) {
    let input = sample_input(tx_count);
    let public = public_replay_v1(&input.records, &input.semantic).unwrap();
    let artifact = prove_block_recursive_v1(&input).unwrap();
    assert_eq!(artifact.public, public);
    (artifact, public)
}

fn cached_two_tx_artifact() -> (RecursiveBlockArtifactV1, RecursiveBlockPublicV1) {
    static CACHE: OnceLock<(RecursiveBlockArtifactV1, RecursiveBlockPublicV1)> = OnceLock::new();
    CACHE.get_or_init(|| prove_artifact(2)).clone()
}

fn base_prefix_statement() -> RecursivePrefixStatementV1 {
    RecursivePrefixStatementV1 {
        tx_count: 0,
        start_state_digest: digest48(0x01, 0),
        end_state_digest: digest48(0x01, 0),
        verified_leaf_commitment: [0u8; 48],
        tx_statements_commitment: digest48(0x02, 0),
        verified_receipt_commitment: [0u8; 48],
        start_tree_commitment: digest48(0x03, 0),
        end_tree_commitment: digest48(0x03, 0),
    }
}

fn sample_leaf_record(tx_index: u32) -> BlockLeafRecordV1 {
    BlockLeafRecordV1 {
        tx_index,
        receipt_statement_hash: digest48(0x10, tx_index),
        receipt_proof_digest: digest48(0x20, tx_index),
        receipt_public_inputs_digest: digest48(0x30, tx_index),
        receipt_verifier_profile: digest48(0x40, tx_index),
        leaf_params_fingerprint: digest48(0x50, tx_index),
        leaf_spec_digest: digest32(0x60, tx_index),
        leaf_relation_id: digest32(0x70, tx_index),
        leaf_shape_digest: digest32(0x80, tx_index),
        leaf_statement_digest: digest48(0x90, tx_index),
        leaf_commitment_digest: digest48(0xa0, tx_index),
        leaf_proof_digest: digest48(0xb0, tx_index),
    }
}

fn step_statement_pair() -> (RecursivePrefixStatementV1, BlockLeafRecordV1, RecursivePrefixStatementV1) {
    let previous = base_prefix_statement();
    let leaf = sample_leaf_record(previous.tx_count);
    let target = RecursivePrefixStatementV1 {
        tx_count: previous.tx_count + 1,
        start_state_digest: previous.start_state_digest,
        end_state_digest: digest48(0x11, 1),
        verified_leaf_commitment: digest48(0x12, 1),
        tx_statements_commitment: previous.tx_statements_commitment,
        verified_receipt_commitment: digest48(0x13, 1),
        start_tree_commitment: previous.start_tree_commitment,
        end_tree_commitment: digest48(0x14, 1),
    };
    (previous, leaf, target)
}

#[test]
fn public_replay_matches_semantic_tuple() {
    let input = sample_input(3);
    let public = public_replay_v1(&input.records, &input.semantic).unwrap();
    assert_eq!(public.tx_count, 3);
    assert_eq!(
        public.tx_statements_commitment,
        input.semantic.tx_statements_commitment
    );
    assert_eq!(
        public.start_shielded_root,
        input.semantic.start_shielded_root
    );
    assert_eq!(public.end_shielded_root, input.semantic.end_shielded_root);
    assert_eq!(public.start_kernel_root, input.semantic.start_kernel_root);
    assert_eq!(public.end_kernel_root, input.semantic.end_kernel_root);
    assert_eq!(public.nullifier_root, input.semantic.nullifier_root);
    assert_eq!(public.da_root, input.semantic.da_root);
    assert_eq!(public.start_tree_commitment, input.semantic.start_tree_commitment);
    assert_eq!(public.end_tree_commitment, input.semantic.end_tree_commitment);
    assert_eq!(serialize_recursive_block_public_v1(&public).len(), 532);
}

#[test]
fn prove_and_verify_recursive_artifact_succeeds() {
    let (artifact, public) = cached_two_tx_artifact();
    let verified = verify_block_recursive_v1(&artifact, &public).unwrap();
    assert_eq!(verified, public);
}

#[test]
fn recursive_artifact_roundtrips_and_exact_consumes() {
    let (artifact, _) = cached_two_tx_artifact();
    let bytes = serialize_recursive_block_artifact_v1(&artifact).unwrap();
    let parsed = deserialize_recursive_block_artifact_v1(&bytes).unwrap();
    assert_eq!(parsed, artifact);
    let public_len = serialize_recursive_block_public_v1(&parsed.public).len();
    assert_eq!(parsed.artifact.header.artifact_bytes as usize, bytes.len() - public_len);
}

#[test]
fn recursive_artifact_rejects_trailing_bytes() {
    let (artifact, _) = cached_two_tx_artifact();
    let mut bytes = serialize_recursive_block_artifact_v1(&artifact).unwrap();
    bytes.extend_from_slice(&[0xde, 0xad]);
    let err = deserialize_recursive_block_artifact_v1(&bytes).unwrap_err();
    assert!(matches!(err, BlockRecursionError::TrailingBytes { .. }));
}

#[test]
fn recursive_artifact_rejects_width_mismatch() {
    let (mut artifact, _) = cached_two_tx_artifact();
    artifact.artifact.header.accumulator_bytes =
        artifact.artifact.header.accumulator_bytes.saturating_add(1);
    let bytes = serialize_recursive_block_artifact_v1(&artifact).unwrap();
    let err = deserialize_recursive_block_artifact_v1(&bytes).unwrap_err();
    assert!(matches!(err, BlockRecursionError::WidthMismatch { .. }));
}

#[test]
fn recursive_artifact_rejects_tampered_statement_digest() {
    let (mut artifact, public) = cached_two_tx_artifact();
    artifact.artifact.header.statement_digest[0] ^= 1;
    let err = verify_block_recursive_v1(&artifact, &public).unwrap_err();
    assert!(matches!(
        err,
        BlockRecursionError::InvalidField("statement_digest")
    ));
}

#[test]
fn recursive_artifact_rejects_wrong_expected_public() {
    let (artifact, mut public) = cached_two_tx_artifact();
    public.tx_count += 1;
    let err = verify_block_recursive_v1(&artifact, &public).unwrap_err();
    assert!(matches!(
        err,
        BlockRecursionError::InvalidField("recursive public tuple mismatch")
    ));
}

#[test]
fn recursive_artifact_rejects_alternate_serializer_under_same_profile() {
    let (mut artifact, public) = cached_two_tx_artifact();
    artifact.artifact.decider_bytes[0] ^= 1;
    let err = verify_block_recursive_v1(&artifact, &public).unwrap_err();
    assert!(!matches!(err, BlockRecursionError::NotImplemented(_)));
}

#[test]
fn proof_bytes_constant_across_tx_counts() {
    let short = serialize_recursive_block_artifact_v1(&prove_artifact(1).0)
        .unwrap()
        .len();
    let long = serialize_recursive_block_artifact_v1(&prove_artifact(5).0)
        .unwrap()
        .len();
    assert_eq!(short, long);
}

#[test]
fn base_a_relation_proves_and_verifies_on_recursive_smallwood_profile() {
    let statement = base_prefix_statement();
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(&statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 8],
        &binding,
    )
    .unwrap();
    verify_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &binding,
        &proof,
    )
    .unwrap();
}

#[test]
fn recursive_proof_envelope_component_checks_reject_tampered_envelope() {
    let statement = base_prefix_statement();
    let relation = BaseARelationV1::new(statement.clone(), statement.clone());
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let binding = hosted_base_binding_bytes_v1(&statement);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 8],
        &binding,
    )
    .unwrap();
    let mut envelope_bytes = encode_smallwood_recursive_proof_envelope_v1(
        &SmallwoodRecursiveProofEnvelopeV1 {
            descriptor,
            proof_bytes: proof,
        },
    )
    .unwrap();
    envelope_bytes[0] ^= 1;
    let err = verify_recursive_proof_envelope_components_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &hosted_recursive_descriptor_v1(
            SmallwoodRecursiveProfileTagV1::A,
            SmallwoodRecursiveRelationKindV1::BaseA,
        ),
        &relation,
        &binding,
        &envelope_bytes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        TransactionCircuitError::ConstraintViolation(_)
            | TransactionCircuitError::ConstraintViolationOwned(_)
    ));
}

#[test]
fn step_b_relation_proves_and_verifies_on_recursive_smallwood_profile() {
    let base_statement = base_prefix_statement();
    let base_relation = BaseARelationV1::new(base_statement.clone(), base_statement.clone());
    let base_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let base_binding = hosted_base_binding_bytes_v1(&base_statement);
    let base_proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &base_descriptor,
        &base_relation,
        &[0u64; 8],
        &base_binding,
    )
    .unwrap();
    let base_envelope_bytes = encode_smallwood_recursive_proof_envelope_v1(
        &SmallwoodRecursiveProofEnvelopeV1 {
            descriptor: base_descriptor.clone(),
            proof_bytes: base_proof,
        },
    )
    .unwrap();
    let base_context = HostedRecursiveProofContextV1::BaseA {
        statement: base_statement.clone(),
        proof_envelope_bytes: base_envelope_bytes,
    };

    let (previous, leaf, target) = step_statement_pair();
    let relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    );
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let binding = hosted_step_binding_bytes_v1(&base_context, &previous, &leaf, &target);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 8],
        &binding,
    )
    .unwrap();
    verify_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &binding,
        &proof,
    )
    .unwrap();
    let step_context = HostedRecursiveProofContextV1::StepB {
        previous_recursive_proof: Box::new(base_context),
        previous_statement: previous,
        leaf_record: leaf,
        target_statement: target,
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor,
                proof_bytes: proof,
            },
        )
        .unwrap(),
    };
    verify_hosted_recursive_proof_context_components_v1(&step_context).unwrap();
}

#[test]
fn step_a_relation_proves_and_verifies_on_recursive_smallwood_profile() {
    let base_statement = base_prefix_statement();
    let base_relation = BaseARelationV1::new(base_statement.clone(), base_statement.clone());
    let base_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::BaseA,
    );
    let base_binding = hosted_base_binding_bytes_v1(&base_statement);
    let base_proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &base_descriptor,
        &base_relation,
        &[0u64; 8],
        &base_binding,
    )
    .unwrap();
    let base_context = HostedRecursiveProofContextV1::BaseA {
        statement: base_statement.clone(),
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor: base_descriptor.clone(),
                proof_bytes: base_proof,
            },
        )
        .unwrap(),
    };
    let (previous, leaf, target) = step_statement_pair();
    let step_b_relation = StepBRelationV1::new(
        base_context.clone(),
        previous.clone(),
        leaf.clone(),
        target.clone(),
    );
    let step_b_descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::B,
        SmallwoodRecursiveRelationKindV1::StepB,
    );
    let step_b_binding = hosted_step_binding_bytes_v1(&base_context, &previous, &leaf, &target);
    let step_b_proof = prove_recursive_statement_v1(
        &recursive_profile_b_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &step_b_descriptor,
        &step_b_relation,
        &[0u64; 8],
        &step_b_binding,
    )
    .unwrap();
    let step_b_context = HostedRecursiveProofContextV1::StepB {
        previous_recursive_proof: Box::new(base_context),
        previous_statement: previous.clone(),
        leaf_record: leaf.clone(),
        target_statement: target.clone(),
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor: step_b_descriptor,
                proof_bytes: step_b_proof,
            },
        )
        .unwrap(),
    };

    let next_leaf = sample_leaf_record(target.tx_count);
    let next_target = RecursivePrefixStatementV1 {
        tx_count: target.tx_count + 1,
        start_state_digest: target.start_state_digest,
        end_state_digest: digest48(0x21, 2),
        verified_leaf_commitment: digest48(0x22, 2),
        tx_statements_commitment: target.tx_statements_commitment,
        verified_receipt_commitment: digest48(0x23, 2),
        start_tree_commitment: target.start_tree_commitment,
        end_tree_commitment: digest48(0x24, 2),
    };
    let relation = StepARelationV1::new(
        step_b_context.clone(),
        target.clone(),
        next_leaf.clone(),
        next_target.clone(),
    );
    let descriptor = hosted_recursive_descriptor_v1(
        SmallwoodRecursiveProfileTagV1::A,
        SmallwoodRecursiveRelationKindV1::StepA,
    );
    let binding = hosted_step_binding_bytes_v1(&step_b_context, &target, &next_leaf, &next_target);
    let proof = prove_recursive_statement_v1(
        &recursive_profile_a_v1(SMALLWOOD_CANDIDATE_VERSION_BINDING),
        &descriptor,
        &relation,
        &[0u64; 8],
        &binding,
    )
    .unwrap();
    let step_a_context = HostedRecursiveProofContextV1::StepA {
        previous_recursive_proof: Box::new(step_b_context),
        previous_statement: target,
        leaf_record: next_leaf,
        target_statement: next_target,
        proof_envelope_bytes: encode_smallwood_recursive_proof_envelope_v1(
            &SmallwoodRecursiveProofEnvelopeV1 {
                descriptor,
                proof_bytes: proof,
            },
        )
        .unwrap(),
    };
    verify_hosted_recursive_proof_context_components_v1(&step_a_context).unwrap();
}
