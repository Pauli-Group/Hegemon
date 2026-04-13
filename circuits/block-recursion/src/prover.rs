use crate::{
    artifacts::{
        deserialize_block_accumulation_transcript_v1, serialize_block_accumulation_transcript_v1,
        BlockAccumulationTranscriptV1, RecursiveBlockArtifactV1,
        BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1,
    },
    relation::{build_block_step_relation_v1, validate_assignment_v1, BlockAssignmentV1},
    BlockRecursionError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRecursiveProverInputV1 {
    pub assignment: BlockAssignmentV1,
    pub transcript: BlockAccumulationTranscriptV1,
}

pub fn prove_block_recursive_v1(
    input: &BlockRecursiveProverInputV1,
) -> Result<RecursiveBlockArtifactV1, BlockRecursionError> {
    validate_assignment_v1(&input.assignment)?;
    build_block_step_relation_v1(&input.assignment.step_statement, &input.assignment.public)?;
    if input.transcript.version != BLOCK_ACCUMULATION_TRANSCRIPT_VERSION_V1 {
        return Err(BlockRecursionError::InvalidVersion {
            what: "block accumulation transcript",
            version: input.transcript.version,
        });
    }
    if input.transcript.step_count != input.assignment.public.tx_count {
        return Err(BlockRecursionError::InvalidField(
            "transcript step_count must match assignment public tx_count",
        ));
    }
    let transcript_bytes = serialize_block_accumulation_transcript_v1(&input.transcript)?;
    let parsed_transcript = deserialize_block_accumulation_transcript_v1(&transcript_bytes)?;
    if parsed_transcript != input.transcript {
        return Err(BlockRecursionError::InvalidField(
            "transcript must round-trip through canonical serializer",
        ));
    }
    Err(BlockRecursionError::NotImplemented(
        "recursive prover backend is not implemented in circuits/block-recursion; validated assignment and canonical transcript only",
    ))
}
