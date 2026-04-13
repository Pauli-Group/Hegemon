use crate::{
    public_replay::RecursiveBlockPublicV1,
    statement::{
        validate_compose_check_v1 as statement_validate_compose_check_v1,
        BlockPrefixStatementV1, BlockStepStatementV1,
    },
    BlockRecursionError, Digest32, Digest48, RecursiveStateV1,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockStepRelationV1 {
    pub relation_id: Digest32,
    pub shape_digest: Digest32,
    pub statement_digest: Digest48,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockAssignmentV1 {
    pub state: RecursiveStateV1,
    pub step_statement: BlockStepStatementV1,
    pub public: RecursiveBlockPublicV1,
}

pub fn build_block_step_relation_v1(
    step_statement: &BlockStepStatementV1,
    public: &RecursiveBlockPublicV1,
) -> Result<BlockStepRelationV1, BlockRecursionError> {
    if step_statement.prefix.tx_count != public.tx_count {
        return Err(BlockRecursionError::InvalidField(
            "step statement prefix must match public tx count",
        ));
    }
    if !step_statement.compose_check.is_valid {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "compose check must be valid",
        ));
    }
    Ok(BlockStepRelationV1 {
        relation_id: step_statement.relation_id,
        shape_digest: step_statement.shape_digest,
        statement_digest: crate::statement::statement_digest_v1(step_statement),
    })
}

pub fn validate_compose_check_v1(
    previous: &BlockPrefixStatementV1,
    step: &BlockPrefixStatementV1,
    target_tx_count: u32,
) -> Result<(), BlockRecursionError> {
    let compose = statement_validate_compose_check_v1(previous, step, target_tx_count)?;
    if !compose.is_valid {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "compose check must be valid",
        ));
    }
    Ok(())
}

pub fn validate_assignment_v1(
    assignment: &BlockAssignmentV1,
) -> Result<(), BlockRecursionError> {
    if assignment.step_statement.prefix.tx_count != assignment.public.tx_count {
        return Err(BlockRecursionError::InvalidField(
            "assignment public tx_count must match step statement",
        ));
    }
    if assignment.state.tx_count != assignment.public.tx_count {
        return Err(BlockRecursionError::InvalidField(
            "state tx_count must match public tx_count",
        ));
    }
    if assignment.state.step_index != assignment.step_statement.step_index {
        return Err(BlockRecursionError::InvalidField(
            "state step index must match statement step index",
        ));
    }
    Ok(())
}
