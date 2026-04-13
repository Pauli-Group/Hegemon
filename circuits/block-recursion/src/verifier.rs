use crate::{
    artifacts::RecursiveBlockArtifactV1,
    public_replay::RecursiveBlockPublicV1,
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
    Ok(artifact.public.clone())
}

