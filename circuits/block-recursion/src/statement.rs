use crate::{
    public_replay::{BlockSemanticInputsV1, RecursiveBlockPublicV1},
    fold_digest32, fold_digest48, BlockRecursionError, Digest32, Digest48,
};

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

pub fn recursive_prefix_statement_digest32_v1(statement: &RecursivePrefixStatementV1) -> Digest32 {
    let encoded = recursive_prefix_statement_bytes_v1(statement);
    fold_digest32(
        b"hegemon.block-recursion.recursive-prefix-statement-d32.v1",
        &[&encoded],
    )
}

pub fn recursive_prefix_statement_digest_v1(statement: &RecursivePrefixStatementV1) -> Digest48 {
    let encoded = recursive_prefix_statement_bytes_v1(statement);
    fold_digest48(
        b"hegemon.block-recursion.recursive-prefix-statement.v1",
        &[&encoded],
    )
}

pub fn recursive_prefix_statement_bytes_v1(statement: &RecursivePrefixStatementV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + (48 * 7));
    out.extend_from_slice(&statement.tx_count.to_le_bytes());
    out.extend_from_slice(&statement.start_state_digest);
    out.extend_from_slice(&statement.end_state_digest);
    out.extend_from_slice(&statement.verified_leaf_commitment);
    out.extend_from_slice(&statement.tx_statements_commitment);
    out.extend_from_slice(&statement.verified_receipt_commitment);
    out.extend_from_slice(&statement.start_tree_commitment);
    out.extend_from_slice(&statement.end_tree_commitment);
    out
}

pub fn recursive_prefix_start_state_digest_v1(
    tx_statements_commitment: Digest48,
    start_tree_commitment: Digest48,
) -> Digest48 {
    fold_digest48(
        b"hegemon.block-recursion.recursive-prefix-start-state.v1",
        &[&tx_statements_commitment, &start_tree_commitment],
    )
}

pub fn recursive_prefix_progress_tree_commitment_v1(
    tx_count: u32,
    start_tree_commitment: Digest48,
    verified_leaf_commitment: Digest48,
    verified_receipt_commitment: Digest48,
) -> Digest48 {
    fold_digest48(
        b"hegemon.block-recursion.recursive-prefix-tree.v1",
        &[
            &tx_count.to_le_bytes(),
            &start_tree_commitment,
            &verified_leaf_commitment,
            &verified_receipt_commitment,
        ],
    )
}

pub fn recursive_prefix_end_state_digest_v1(
    tx_count: u32,
    start_state_digest: Digest48,
    verified_leaf_commitment: Digest48,
    tx_statements_commitment: Digest48,
    verified_receipt_commitment: Digest48,
    start_tree_commitment: Digest48,
    end_tree_commitment: Digest48,
) -> Digest48 {
    fold_digest48(
        b"hegemon.block-recursion.recursive-prefix-end-state.v1",
        &[
            &tx_count.to_le_bytes(),
            &start_state_digest,
            &verified_leaf_commitment,
            &tx_statements_commitment,
            &verified_receipt_commitment,
            &start_tree_commitment,
            &end_tree_commitment,
        ],
    )
}

pub fn recursive_prefix_statement_from_parts_v1(
    tx_count: u32,
    tx_statements_commitment: Digest48,
    verified_leaf_commitment: Digest48,
    verified_receipt_commitment: Digest48,
    start_tree_commitment: Digest48,
    end_tree_commitment: Digest48,
) -> RecursivePrefixStatementV1 {
    let start_state_digest =
        recursive_prefix_start_state_digest_v1(tx_statements_commitment, start_tree_commitment);
    let end_state_digest = if tx_count == 0
        && verified_leaf_commitment == [0u8; 48]
        && verified_receipt_commitment == [0u8; 48]
        && end_tree_commitment == start_tree_commitment
    {
        start_state_digest
    } else {
        recursive_prefix_end_state_digest_v1(
            tx_count,
            start_state_digest,
            verified_leaf_commitment,
            tx_statements_commitment,
            verified_receipt_commitment,
            start_tree_commitment,
            end_tree_commitment,
        )
    };
    RecursivePrefixStatementV1 {
        tx_count,
        start_state_digest,
        end_state_digest,
        verified_leaf_commitment,
        tx_statements_commitment,
        verified_receipt_commitment,
        start_tree_commitment,
        end_tree_commitment,
    }
}

pub fn recursive_prefix_statement_from_public_v1(
    public: &RecursiveBlockPublicV1,
) -> RecursivePrefixStatementV1 {
    recursive_prefix_statement_from_parts_v1(
        public.tx_count,
        public.tx_statements_commitment,
        public.verified_leaf_commitment,
        public.verified_receipt_commitment,
        public.start_tree_commitment,
        public.end_tree_commitment,
    )
}

pub fn recursive_prefix_base_statement_v1(
    semantic: &BlockSemanticInputsV1,
) -> RecursivePrefixStatementV1 {
    recursive_prefix_statement_from_parts_v1(
        0,
        semantic.tx_statements_commitment,
        [0u8; 48],
        [0u8; 48],
        semantic.start_tree_commitment,
        semantic.start_tree_commitment,
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
