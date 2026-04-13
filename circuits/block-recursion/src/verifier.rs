use crate::{
    artifacts::{
        compress_transcript_digest_v1, decider_profile_digest_v1,
        recursive_decider_serializer_digest_v1, recursive_lcccs_serializer_digest_v1,
        serialize_recursive_block_inner_artifact_v1, RecursiveBlockArtifactV1,
        RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
        RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1,
    },
    public_replay::RecursiveBlockPublicV1,
    relation::{
        ensure_expected_relation_v1, ensure_expected_shape_v1, prefix_statement_v1,
        recursive_block_shape_v1,
    },
    BlockRecursionError,
};
use superneo_backend_lattice::{recursive_backend_v2, RecursiveLatticeDeciderProof};
use superneo_core::{
    deserialize_lcccs_instance, serialize_decider_profile, serialize_lcccs_instance, LcccsInstance,
    RecursiveBackend,
};
use superneo_hegemon::native_backend_params;

fn static_error(prefix: &'static str, err: impl core::fmt::Display) -> BlockRecursionError {
    BlockRecursionError::InvalidField(Box::leak(format!("{prefix}: {err}").into_boxed_str()))
}

pub fn verify_block_recursive_v1(
    artifact: &RecursiveBlockArtifactV1,
    expected_public: &RecursiveBlockPublicV1,
) -> Result<RecursiveBlockPublicV1, BlockRecursionError> {
    if artifact.public != *expected_public {
        return Err(BlockRecursionError::InvalidField(
            "recursive public tuple mismatch",
        ));
    }
    let inner = &artifact.artifact;
    if inner.header.version != RECURSIVE_BLOCK_ARTIFACT_VERSION_V1 {
        return Err(BlockRecursionError::InvalidVersion {
            what: "recursive block artifact header",
            version: inner.header.version,
        });
    }
    if inner.header.proof_kind != RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1 {
        return Err(BlockRecursionError::InvalidField("proof_kind"));
    }
    if inner.header.accumulator_bytes as usize != inner.accumulator_bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "accumulator_bytes",
            expected: inner.header.accumulator_bytes as usize,
            actual: inner.accumulator_bytes.len(),
        });
    }
    if inner.header.decider_bytes as usize != inner.decider_bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "decider_bytes",
            expected: inner.header.decider_bytes as usize,
            actual: inner.decider_bytes.len(),
        });
    }
    let canonical_artifact_len = serialize_recursive_block_inner_artifact_v1(inner)?.len();
    if inner.header.artifact_bytes as usize != canonical_artifact_len {
        return Err(BlockRecursionError::WidthMismatch {
            what: "artifact_bytes",
            expected: inner.header.artifact_bytes as usize,
            actual: canonical_artifact_len,
        });
    }
    let header_bytes = crate::serialize_header_dec_step_v1(&inner.header)?;
    if inner.header.header_bytes as usize != header_bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "header_bytes",
            expected: inner.header.header_bytes as usize,
            actual: header_bytes.len(),
        });
    }
    if inner.header.statement_digest
        != crate::recursive_block_public_statement_digest_v1(expected_public)
    {
        return Err(BlockRecursionError::InvalidField("statement_digest"));
    }

    let params = native_backend_params();
    let backend = recursive_backend_v2(params.clone());
    let shape = recursive_block_shape_v1();
    let security = params.security_params();
    let (_pk, vk) = backend
        .setup_recursive(&security, &shape)
        .map_err(|err| static_error("recursive setup failed", err))?;
    let decider_profile = backend
        .recursive_decider_profile(&security, &shape)
        .map_err(|err| static_error("recursive decider profile failed", err))?;
    let decider_profile_bytes = serialize_decider_profile(&decider_profile)
        .map_err(|err| static_error("serialize decider profile failed", err))?;
    if inner.header.decider_profile_digest != decider_profile_digest_v1(&decider_profile_bytes) {
        return Err(BlockRecursionError::InvalidField("decider_profile_digest"));
    }
    if inner.header.accumulator_serializer_digest != recursive_lcccs_serializer_digest_v1() {
        return Err(BlockRecursionError::InvalidField(
            "accumulator_serializer_digest",
        ));
    }
    if inner.header.decider_serializer_digest != recursive_decider_serializer_digest_v1() {
        return Err(BlockRecursionError::InvalidField(
            "decider_serializer_digest",
        ));
    }

    let terminal: LcccsInstance<
        superneo_backend_lattice::LatticeCommitment,
        p3_goldilocks::Goldilocks,
    > = deserialize_lcccs_instance(&inner.accumulator_bytes)
        .map_err(|err| static_error("deserialize terminal accumulator failed", err))?;
    let accumulator_roundtrip = serialize_lcccs_instance(&terminal)
        .map_err(|err| static_error("serialize terminal accumulator failed", err))?;
    if accumulator_roundtrip != inner.accumulator_bytes {
        return Err(BlockRecursionError::InvalidField(
            "accumulator_bytes must use canonical serializer",
        ));
    }
    ensure_expected_relation_v1(terminal.relation_id)?;
    ensure_expected_shape_v1(terminal.shape_digest)?;

    let decider_proof = RecursiveLatticeDeciderProof::from_canonical_bytes(&inner.decider_bytes)
        .map_err(|err| static_error("deserialize decider proof failed", err))?;
    let decider_roundtrip = decider_proof
        .to_canonical_bytes()
        .map_err(|err| static_error("serialize decider proof failed", err))?;
    if decider_roundtrip != inner.decider_bytes {
        return Err(BlockRecursionError::InvalidField(
            "decider_bytes must use canonical serializer",
        ));
    }
    if inner.header.transcript_digest
        != compress_transcript_digest_v1(&decider_proof.transcript_digest)
    {
        return Err(BlockRecursionError::InvalidField("transcript_digest"));
    }

    let statement = prefix_statement_v1(expected_public);
    if terminal.statement != statement {
        return Err(BlockRecursionError::InvalidField(
            "terminal statement mismatch",
        ));
    }
    backend
        .verify_decider(&vk, &decider_profile, &statement, &terminal, &decider_proof)
        .map_err(|err| static_error("verify recursive decider failed", err))?;
    Ok(expected_public.clone())
}
