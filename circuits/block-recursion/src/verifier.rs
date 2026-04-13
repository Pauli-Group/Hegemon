use crate::{
    artifacts::{
        block_accumulation_transcript_digest_v1,
        block_accumulation_transcript_serializer_digest_v1,
        deserialize_block_accumulation_transcript_v1,
        header_dec_step_profile_digest_v1,
        recursive_block_public_statement_digest_v1,
        serialize_header_dec_step_v1,
        RECURSIVE_BLOCK_ARTIFACT_VERSION_V1, RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1,
        RecursiveBlockArtifactV1, BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1,
    },
    public_replay::RecursiveBlockPublicV1,
    state::{
        deserialize_recursive_state_v1, recursive_state_serializer_digest_v1,
        serialize_recursive_state_v1,
    },
    BlockRecursionError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecursiveVerificationError {
    pub message: &'static str,
}

impl core::fmt::Display for BlockRecursiveVerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BlockRecursiveVerificationError {}

pub fn verify_block_recursive_v1(
    artifact: &RecursiveBlockArtifactV1,
) -> Result<RecursiveBlockPublicV1, BlockRecursionError> {
    if artifact.header.version != RECURSIVE_BLOCK_ARTIFACT_VERSION_V1 {
        return Err(BlockRecursionError::InvalidVersion {
            what: "recursive block artifact header",
            version: artifact.header.version,
        });
    }
    if artifact.header.proof_kind != RECURSIVE_BLOCK_PROOF_KIND_STRUCTURAL_V1 {
        return Err(BlockRecursionError::InvalidField("proof_kind"));
    }
    if artifact.header.accumulator_bytes as usize != artifact.accumulator_bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "accumulator_bytes",
            expected: artifact.header.accumulator_bytes as usize,
            actual: artifact.accumulator_bytes.len(),
        });
    }
    if artifact.header.decider_bytes as usize != artifact.decider_bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "decider_bytes",
            expected: artifact.header.decider_bytes as usize,
            actual: artifact.decider_bytes.len(),
        });
    }
    if artifact.header.artifact_bytes == 0 {
        return Err(BlockRecursionError::InvalidField(
            "artifact_bytes must be non-zero",
        ));
    }
    let canonical_artifact_len = crate::serialize_recursive_block_artifact_v1(artifact)?.len();
    if artifact.header.artifact_bytes as usize != canonical_artifact_len {
        return Err(BlockRecursionError::WidthMismatch {
            what: "artifact_bytes",
            expected: artifact.header.artifact_bytes as usize,
            actual: canonical_artifact_len,
        });
    }
    let header_bytes = serialize_header_dec_step_v1(&artifact.header)?;
    if artifact.header.header_bytes as usize != header_bytes.len() {
        return Err(BlockRecursionError::WidthMismatch {
            what: "header_bytes",
            expected: artifact.header.header_bytes as usize,
            actual: header_bytes.len(),
        });
    }
    if artifact.header.accumulator_serializer_digest != recursive_state_serializer_digest_v1() {
        return Err(BlockRecursionError::InvalidField(
            "accumulator_serializer_digest",
        ));
    }
    if artifact.header.decider_serializer_digest
        != block_accumulation_transcript_serializer_digest_v1()
    {
        return Err(BlockRecursionError::InvalidField("decider_serializer_digest"));
    }
    if artifact.header.statement_digest
        != recursive_block_public_statement_digest_v1(&artifact.public)
    {
        return Err(BlockRecursionError::InvalidField("statement_digest"));
    }
    if artifact.header.decider_profile_digest
        != header_dec_step_profile_digest_v1(&artifact.header)
    {
        return Err(BlockRecursionError::InvalidField("decider_profile_digest"));
    }

    let accumulator = deserialize_recursive_state_v1(&artifact.accumulator_bytes)?;
    let accumulator_roundtrip = serialize_recursive_state_v1(&accumulator)?;
    if accumulator_roundtrip != artifact.accumulator_bytes {
        return Err(BlockRecursionError::InvalidField(
            "accumulator_bytes must use canonical serializer",
        ));
    }
    let transcript = deserialize_block_accumulation_transcript_v1(&artifact.decider_bytes)?;
    let transcript_roundtrip = crate::serialize_block_accumulation_transcript_v1(&transcript)?;
    if transcript_roundtrip != artifact.decider_bytes {
        return Err(BlockRecursionError::InvalidField(
            "decider_bytes must use canonical serializer",
        ));
    }
    if transcript.version != BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1 {
        return Err(BlockRecursionError::InvalidVersion {
            what: "block accumulation transcript",
            version: transcript.version,
        });
    }
    if artifact.header.transcript_digest != block_accumulation_transcript_digest_v1(&transcript)? {
        return Err(BlockRecursionError::InvalidField("transcript_digest"));
    }
    if transcript.step_count != artifact.public.tx_count {
        return Err(BlockRecursionError::InvalidField(
            "transcript step_count must match public tx_count",
        ));
    }
    if accumulator.step_index != artifact.public.tx_count {
        return Err(BlockRecursionError::InvalidField(
            "terminal accumulator step_index must match public tx_count",
        ));
    }
    if accumulator.tx_count != artifact.public.tx_count {
        return Err(BlockRecursionError::InvalidField(
            "terminal accumulator tx_count must match public tx_count",
        ));
    }
    if accumulator.statement_commitment != artifact.public.tx_statements_commitment {
        return Err(BlockRecursionError::InvalidField(
            "accumulator statement_commitment",
        ));
    }
    if accumulator.leaf_commitment != artifact.public.verified_leaf_commitment {
        return Err(BlockRecursionError::InvalidField("accumulator leaf_commitment"));
    }
    if accumulator.receipt_commitment != artifact.public.verified_receipt_commitment {
        return Err(BlockRecursionError::InvalidField(
            "accumulator receipt_commitment",
        ));
    }
    if accumulator.frontier_commitment != artifact.public.frontier_commitment {
        return Err(BlockRecursionError::InvalidField(
            "accumulator frontier_commitment",
        ));
    }
    if accumulator.history_commitment != artifact.public.history_commitment {
        return Err(BlockRecursionError::InvalidField(
            "accumulator history_commitment",
        ));
    }
    if accumulator.nullifier_root != artifact.public.nullifier_root {
        return Err(BlockRecursionError::InvalidField("accumulator nullifier_root"));
    }
    if accumulator.da_root != artifact.public.da_root {
        return Err(BlockRecursionError::InvalidField("accumulator da_root"));
    }

    Err(BlockRecursionError::NotImplemented(
        "recursive decider verification is not implemented in circuits/block-recursion; structural header/state/transcript checks passed",
    ))
}
