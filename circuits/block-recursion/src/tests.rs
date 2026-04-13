use super::{
    deserialize_recursive_block_artifact_v1,
    header_dec_step_profile_digest_v1, recursive_block_public_statement_digest_v1,
    recursive_state_serializer_digest_v1, serialize_recursive_state_v1,
    public_replay_v1, serialize_block_accumulation_transcript_v1,
    serialize_recursive_block_artifact_v1, verify_block_recursive_v1,
    block_accumulation_transcript_digest_v1,
    block_accumulation_transcript_serializer_digest_v1,
    BlockAccumulationTranscriptV1, BlockAssignmentV1, BlockLeafRecordV1,
    BlockPrefixStatementV1, BlockRecursionError, BlockStepStatementV1, ComposeCheckV1,
    HeaderDecStepV1, RecursiveBlockArtifactV1, RecursiveBlockPublicV1, RecursiveStateV1,
    BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1, RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
    RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1,
};
use super::relation::build_block_step_relation_v1;
use super::prover::{prove_block_recursive_v1, BlockRecursiveProverInputV1};

fn sample_public(tx_count: u32) -> RecursiveBlockPublicV1 {
    RecursiveBlockPublicV1 {
        tx_count,
        tx_statements_commitment: [1; 48],
        verified_leaf_commitment: [2; 48],
        verified_receipt_commitment: [3; 48],
        start_shielded_root: [4; 32],
        end_shielded_root: [5; 32],
        start_kernel_root: [6; 32],
        end_kernel_root: [7; 32],
        nullifier_root: [8; 32],
        da_root: [9; 32],
        frontier_commitment: [10; 32],
        history_commitment: [11; 32],
    }
}

fn sample_step_statement(tx_count: u32) -> BlockStepStatementV1 {
    let prefix = BlockPrefixStatementV1 {
        tx_count,
        tx_statements_commitment: [1; 48],
        leaf_commitment: [2; 48],
        receipt_commitment: [3; 48],
        frontier_commitment: [4; 32],
        history_commitment: [5; 32],
        nullifier_root: [6; 32],
        da_root: [7; 32],
    };
    BlockStepStatementV1 {
        version: 1,
        relation_id: [8; 32],
        shape_digest: [9; 32],
        step_index: 0,
        prefix,
        public_inputs: vec![[10; 32]],
        compose_check: ComposeCheckV1::new(tx_count, 0, tx_count).unwrap(),
    }
}

fn sample_artifact(tx_count: u32) -> RecursiveBlockArtifactV1 {
    let public = sample_public(tx_count);
    let accumulator = RecursiveStateV1 {
        step_index: tx_count,
        tx_count,
        statement_commitment: public.tx_statements_commitment,
        leaf_commitment: public.verified_leaf_commitment,
        receipt_commitment: public.verified_receipt_commitment,
        frontier_commitment: public.frontier_commitment,
        history_commitment: public.history_commitment,
        nullifier_root: public.nullifier_root,
        da_root: public.da_root,
    };
    let accumulator_bytes = serialize_recursive_state_v1(&accumulator).unwrap();
    let transcript = BlockAccumulationTranscriptV1 {
        version: BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1,
        step_count: tx_count,
        transcript_bytes: vec![0xa1, 0xb2, 0xc3, tx_count as u8],
    };
    let decider_bytes = serialize_block_accumulation_transcript_v1(&transcript).unwrap();
    let mut header = HeaderDecStepV1 {
        version: RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
        proof_kind: RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1,
        header_bytes: 0,
        artifact_bytes: 0,
        relation_id: [8; 32],
        shape_digest: [9; 32],
        statement_digest: recursive_block_public_statement_digest_v1(&public),
        decider_profile_digest: [0; 32],
        accumulator_serializer_digest: recursive_state_serializer_digest_v1(),
        decider_serializer_digest: block_accumulation_transcript_serializer_digest_v1(),
        transcript_digest: block_accumulation_transcript_digest_v1(&transcript).unwrap(),
        accumulator_bytes: accumulator_bytes.len() as u32,
        decider_bytes: decider_bytes.len() as u32,
    };
    header.header_bytes = super::serialize_header_dec_step_v1(&header).unwrap().len() as u32;
    let artifact_len = serialize_recursive_block_artifact_v1(&RecursiveBlockArtifactV1 {
        header: header.clone(),
        public: public.clone(),
        accumulator_bytes: accumulator_bytes.clone(),
        decider_bytes: decider_bytes.clone(),
    })
    .unwrap()
    .len() as u32;
    header.artifact_bytes = artifact_len;
    header.decider_profile_digest = header_dec_step_profile_digest_v1(&header);
    deserialize_recursive_block_artifact_v1(
        &serialize_recursive_block_artifact_v1(&RecursiveBlockArtifactV1 {
            header,
            public,
            accumulator_bytes,
            decider_bytes,
        })
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn recursive_verifier_fails_closed_without_backend() {
    let artifact = sample_artifact(2);
    let err = verify_block_recursive_v1(&artifact).unwrap_err();
    assert!(matches!(err, BlockRecursionError::NotImplemented(_)));
}

#[test]
fn recursive_artifact_rejects_legacy_linear_payload() {
    let mut artifact = sample_artifact(2);
    artifact.accumulator_bytes = vec![0u8; artifact.accumulator_bytes.len()];
    let err = verify_block_recursive_v1(&artifact).unwrap_err();
    assert!(!matches!(err, BlockRecursionError::NotImplemented(_)));
}

#[test]
fn recursive_artifact_rejects_tampered_profile_digest() {
    let mut artifact = sample_artifact(2);
    artifact.header.decider_profile_digest[0] ^= 1;
    let err = verify_block_recursive_v1(&artifact).unwrap_err();
    assert!(!matches!(err, BlockRecursionError::NotImplemented(_)));
}

#[test]
fn recursive_artifact_rejects_tampered_transcript_digest() {
    let mut artifact = sample_artifact(2);
    artifact.header.transcript_digest[0] ^= 1;
    let err = verify_block_recursive_v1(&artifact).unwrap_err();
    assert!(!matches!(err, BlockRecursionError::NotImplemented(_)));
}

#[test]
fn recursive_artifact_rejects_wrong_proof_kind() {
    let mut artifact = sample_artifact(2);
    artifact.header.proof_kind ^= 1;
    let err = verify_block_recursive_v1(&artifact).unwrap_err();
    assert!(!matches!(err, BlockRecursionError::NotImplemented(_)));
}

#[test]
fn recursive_artifact_rejects_wrong_terminal_step_index() {
    let mut artifact = sample_artifact(2);
    let mut state = super::deserialize_recursive_state_v1(&artifact.accumulator_bytes).unwrap();
    state.step_index = 1;
    artifact.accumulator_bytes = serialize_recursive_state_v1(&state).unwrap();
    artifact.header.accumulator_bytes = artifact.accumulator_bytes.len() as u32;
    let err = verify_block_recursive_v1(&artifact).unwrap_err();
    assert!(!matches!(err, BlockRecursionError::NotImplemented(_)));
}

#[test]
fn public_replay_matches_consensus_tuple() {
    let records = vec![
        BlockLeafRecordV1 {
            tx_index: 0,
            tx_statement_commitment: [1; 48],
            verified_leaf_commitment: [2; 48],
            verified_receipt_commitment: [3; 48],
            start_shielded_root: [4; 32],
            end_shielded_root: [5; 32],
            start_kernel_root: [6; 32],
            end_kernel_root: [7; 32],
            nullifier_root: [8; 32],
            da_root: [9; 32],
        },
        BlockLeafRecordV1 {
            tx_index: 1,
            tx_statement_commitment: [11; 48],
            verified_leaf_commitment: [12; 48],
            verified_receipt_commitment: [13; 48],
            start_shielded_root: [14; 32],
            end_shielded_root: [15; 32],
            start_kernel_root: [16; 32],
            end_kernel_root: [17; 32],
            nullifier_root: [18; 32],
            da_root: [19; 32],
        },
    ];
    let public = public_replay_v1(&records).unwrap();
    assert_eq!(public.tx_count, 2);
    assert_eq!(public.start_shielded_root, [4; 32]);
    assert_eq!(public.end_shielded_root, [15; 32]);
    assert_eq!(public.nullifier_root, [18; 32]);
}

#[test]
fn recursive_artifact_roundtrips_and_exact_consumes() {
    let artifact = sample_artifact(2);
    let bytes = serialize_recursive_block_artifact_v1(&artifact).unwrap();
    let parsed = deserialize_recursive_block_artifact_v1(&bytes).unwrap();
    assert_eq!(parsed.public, artifact.public);
    assert_eq!(parsed.accumulator_bytes, artifact.accumulator_bytes);
    assert_eq!(parsed.decider_bytes, artifact.decider_bytes);
    assert_eq!(parsed.header.accumulator_bytes, artifact.header.accumulator_bytes);
    assert_eq!(parsed.header.decider_bytes, artifact.header.decider_bytes);
    assert!(parsed.header.header_bytes > 0);
    assert_eq!(parsed.header.artifact_bytes as usize, bytes.len());
}

#[test]
fn recursive_artifact_rejects_trailing_bytes() {
    let artifact = sample_artifact(2);
    let mut bytes = serialize_recursive_block_artifact_v1(&artifact).unwrap();
    bytes.extend_from_slice(&[0xde, 0xad]);
    let err = deserialize_recursive_block_artifact_v1(&bytes).unwrap_err();
    assert!(matches!(err, BlockRecursionError::TrailingBytes { .. }));
}

#[test]
fn recursive_artifact_rejects_width_mismatch() {
    let mut artifact = sample_artifact(2);
    artifact.header.accumulator_bytes = 8;
    let bytes = serialize_recursive_block_artifact_v1(&artifact).unwrap();
    let err = deserialize_recursive_block_artifact_v1(&bytes).unwrap_err();
    assert!(matches!(err, BlockRecursionError::WidthMismatch { .. }));
}

#[test]
fn recursive_artifact_rejects_alternate_serializer_under_same_profile() {
    let mut artifact = sample_artifact(2);
    artifact.decider_bytes[0] ^= 1;
    let err = verify_block_recursive_v1(&artifact).unwrap_err();
    assert!(!matches!(err, BlockRecursionError::NotImplemented(_)));
}

#[test]
fn proof_bytes_constant_across_tx_counts() {
    let a = serialize_recursive_block_artifact_v1(&sample_artifact(2)).unwrap().len();
    let b = serialize_recursive_block_artifact_v1(&sample_artifact(7)).unwrap().len();
    assert_eq!(a, b);
}

#[test]
fn recursive_toy_relation_is_structurally_valid() {
    let public = sample_public(2);
    let step = sample_step_statement(2);
    let relation = build_block_step_relation_v1(&step, &public).unwrap();
    assert_eq!(relation.relation_id, [8; 32]);
}

#[test]
fn recursive_toy_relation_rejects_wrong_witness() {
    let public = sample_public(3);
    let step = sample_step_statement(2);
    assert!(build_block_step_relation_v1(&step, &public).is_err());
}

#[test]
fn proof_stub_returns_not_implemented() {
    let public = sample_public(2);
    let step = sample_step_statement(2);
    let state = RecursiveStateV1 {
        step_index: 0,
        tx_count: 2,
        statement_commitment: public.tx_statements_commitment,
        leaf_commitment: public.verified_leaf_commitment,
        receipt_commitment: public.verified_receipt_commitment,
        frontier_commitment: public.frontier_commitment,
        history_commitment: public.history_commitment,
        nullifier_root: public.nullifier_root,
        da_root: public.da_root,
    };
    let assignment = BlockAssignmentV1 {
        state,
        step_statement: step,
        public,
    };
    let input = BlockRecursiveProverInputV1 {
        assignment,
        transcript: BlockAccumulationTranscriptV1 {
            version: 1,
            step_count: 2,
            transcript_bytes: vec![],
        },
    };
    let err = prove_block_recursive_v1(&input).unwrap_err();
    assert!(matches!(err, BlockRecursionError::NotImplemented(_)));
}
