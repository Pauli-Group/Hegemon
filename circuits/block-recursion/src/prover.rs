use crate::{
    artifacts::{BlockAccumulationTranscriptV1, RecursiveBlockArtifactV1},
    relation::{validate_assignment_v1, BlockAssignmentV1},
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
    Err(BlockRecursionError::NotImplemented(
        "recursive prover is scaffold-only in circuits/block-recursion",
    ))
}
