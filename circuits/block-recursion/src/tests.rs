use super::{
    deserialize_block_accumulation_transcript_v1, deserialize_recursive_block_artifact_v1,
    public_replay_v1, serialize_block_accumulation_transcript_v1,
    serialize_recursive_block_artifact_v1, verify_block_recursive_v1,
    BlockAccumulationTranscriptV1, BlockAssignmentV1, BlockLeafRecordV1,
    BlockPrefixStatementV1, BlockRecursionError, BlockStepStatementV1, ComposeCheckV1,
    HeaderDecStepV1, RecursiveBlockArtifactV1, RecursiveBlockPublicV1, RecursiveStateV1,
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
    let header = HeaderDecStepV1 {
        version: 1,
        proof_kind: 1,
        header_bytes: 0,
        artifact_bytes: 0,
        relation_id: [8; 32],
        shape_digest: [9; 32],
        statement_digest: [12; 48],
        decider_profile_digest: [13; 32],
        accumulator_serializer_digest: [14; 32],
        decider_serializer_digest: [15; 32],
        transcript_digest: [16; 32],
        accumulator_bytes: 4,
        decider_bytes: 6,
    };
    RecursiveBlockArtifactV1 {
        header,
        public,
        accumulator_bytes: vec![1, 2, 3, 4],
        decider_bytes: vec![5, 6, 7, 8, 9, 10],
    }
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
    let transcript = BlockAccumulationTranscriptV1 {
        version: 1,
        step_count: 2,
        transcript_bytes: vec![1, 2, 3, 4],
    };
    let bytes = serialize_block_accumulation_transcript_v1(&transcript).unwrap();
    let parsed = deserialize_block_accumulation_transcript_v1(&bytes).unwrap();
    assert_eq!(parsed, transcript);
    let mut bad = bytes.clone();
    bad[0] ^= 1;
    assert!(deserialize_block_accumulation_transcript_v1(&bad).is_err());
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
fn recursive_decider_rejects_tampered_profile() {
    let mut artifact = sample_artifact(2);
    artifact.decider_bytes.push(99);
    assert!(verify_block_recursive_v1(&artifact).is_err());
}

#[test]
fn proof_stub_returns_not_implemented() {
    let public = sample_public(2);
    let step = sample_step_statement(2);
    let state = RecursiveStateV1::genesis(2);
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
