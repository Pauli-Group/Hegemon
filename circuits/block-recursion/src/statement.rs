use crate::{fold_digest48, BlockRecursionError, Digest32, Digest48};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursivePrefixStatementV1 {
    pub tx_count: u32,
    pub start_state_digest: Digest48,
    pub end_state_digest: Digest48,
    pub verified_leaf_commitment: Digest48,
    pub tx_statements_commitment: Digest48,
    pub verified_receipt_commitment: Digest48,
    pub start_tree_commitment: Digest48,
    pub end_tree_commitment: Digest48,
}

pub fn recursive_prefix_statement_digest_v1(statement: &RecursivePrefixStatementV1) -> Digest48 {
    let tx_count = statement.tx_count.to_le_bytes();
    fold_digest48(
        b"hegemon.block-recursion.recursive-prefix-statement.v1",
        &[
            &tx_count,
            &statement.start_state_digest,
            &statement.end_state_digest,
            &statement.verified_leaf_commitment,
            &statement.tx_statements_commitment,
            &statement.verified_receipt_commitment,
            &statement.start_tree_commitment,
            &statement.end_tree_commitment,
        ],
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPrefixStatementV1 {
    pub tx_count: u32,
    pub tx_statements_commitment: Digest48,
    pub leaf_commitment: Digest48,
    pub receipt_commitment: Digest48,
    pub start_tree_commitment: Digest48,
    pub end_tree_commitment: Digest48,
    pub nullifier_root: Digest48,
    pub da_root: Digest48,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposeCheckV1 {
    pub previous_tx_count: u32,
    pub step_tx_count: u32,
    pub target_tx_count: u32,
    pub is_valid: bool,
}

impl ComposeCheckV1 {
    pub fn new(
        previous_tx_count: u32,
        step_tx_count: u32,
        target_tx_count: u32,
    ) -> Result<Self, BlockRecursionError> {
        let is_valid = previous_tx_count.saturating_add(step_tx_count) == target_tx_count;
        Ok(Self {
            previous_tx_count,
            step_tx_count,
            target_tx_count,
            is_valid,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockStepStatementV1 {
    pub version: u16,
    pub relation_id: Digest32,
    pub shape_digest: Digest32,
    pub step_index: u32,
    pub prefix: BlockPrefixStatementV1,
    pub public_inputs: Vec<Digest32>,
    pub compose_check: ComposeCheckV1,
}

pub fn statement_digest_v1(statement: &BlockStepStatementV1) -> Digest48 {
    let mut chunks: Vec<&[u8]> = Vec::new();
    let version = statement.version.to_le_bytes();
    let step_index = statement.step_index.to_le_bytes();
    let prefix_tx_count = statement.prefix.tx_count.to_le_bytes();
    let previous_tx_count = statement.compose_check.previous_tx_count.to_le_bytes();
    let step_tx_count = statement.compose_check.step_tx_count.to_le_bytes();
    let target_tx_count = statement.compose_check.target_tx_count.to_le_bytes();
    let public_inputs_len = (statement.public_inputs.len() as u32).to_le_bytes();
    let compose_valid = [statement.compose_check.is_valid as u8];

    chunks.push(&version);
    chunks.push(&statement.relation_id);
    chunks.push(&statement.shape_digest);
    chunks.push(&step_index);
    chunks.push(&prefix_tx_count);
    chunks.push(&statement.prefix.tx_statements_commitment);
    chunks.push(&statement.prefix.leaf_commitment);
    chunks.push(&statement.prefix.receipt_commitment);
    chunks.push(&statement.prefix.start_tree_commitment);
    chunks.push(&statement.prefix.end_tree_commitment);
    chunks.push(&statement.prefix.nullifier_root);
    chunks.push(&statement.prefix.da_root);
    chunks.push(&previous_tx_count);
    chunks.push(&step_tx_count);
    chunks.push(&target_tx_count);
    chunks.push(&compose_valid);
    chunks.push(&public_inputs_len);
    for input in &statement.public_inputs {
        chunks.push(input);
    }
    fold_digest48(b"block_step_statement_v1", &chunks)
}

pub fn validate_compose_check_v1(
    previous: &BlockPrefixStatementV1,
    step: &BlockPrefixStatementV1,
    target_tx_count: u32,
) -> Result<ComposeCheckV1, BlockRecursionError> {
    let compose = ComposeCheckV1::new(previous.tx_count, step.tx_count, target_tx_count)?;
    if !compose.is_valid {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "prefix counts do not compose",
        ));
    }
    Ok(compose)
}
