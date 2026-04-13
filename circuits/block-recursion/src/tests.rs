use std::sync::OnceLock;

use super::{
    deserialize_recursive_block_artifact_v1, prove_block_recursive_v1, public_replay_v1,
    serialize_recursive_block_artifact_v1, verify_block_recursive_v1, BlockLeafRecordV1,
    BlockRecursionError, BlockRecursiveProverInputV1, BlockSemanticInputsV1,
    RecursiveBlockArtifactV1, RecursiveBlockPublicV1,
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
    assert_eq!(parsed.header.artifact_bytes as usize, bytes.len());
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
    artifact.header.accumulator_bytes = artifact.header.accumulator_bytes.saturating_add(1);
    let bytes = serialize_recursive_block_artifact_v1(&artifact).unwrap();
    let err = deserialize_recursive_block_artifact_v1(&bytes).unwrap_err();
    assert!(matches!(err, BlockRecursionError::WidthMismatch { .. }));
}

#[test]
fn recursive_artifact_rejects_tampered_statement_digest() {
    let (mut artifact, public) = cached_two_tx_artifact();
    artifact.header.statement_digest[0] ^= 1;
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
    artifact.decider_bytes[0] ^= 1;
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
