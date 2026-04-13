use crate::{fold_digest32, fold_digest48, Digest32, Digest48, BlockRecursionError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockLeafRecordV1 {
    pub tx_index: u32,
    pub tx_statement_commitment: Digest48,
    pub verified_leaf_commitment: Digest48,
    pub verified_receipt_commitment: Digest48,
    pub start_shielded_root: Digest32,
    pub end_shielded_root: Digest32,
    pub start_kernel_root: Digest32,
    pub end_kernel_root: Digest32,
    pub nullifier_root: Digest32,
    pub da_root: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveBlockPublicV1 {
    pub tx_count: u32,
    pub tx_statements_commitment: Digest48,
    pub verified_leaf_commitment: Digest48,
    pub verified_receipt_commitment: Digest48,
    pub start_shielded_root: Digest32,
    pub end_shielded_root: Digest32,
    pub start_kernel_root: Digest32,
    pub end_kernel_root: Digest32,
    pub nullifier_root: Digest32,
    pub da_root: Digest32,
    pub frontier_commitment: Digest32,
    pub history_commitment: Digest32,
}

pub fn public_replay_v1(records: &[BlockLeafRecordV1]) -> Result<RecursiveBlockPublicV1, BlockRecursionError> {
    let mut tx_statements: Vec<&[u8]> = Vec::with_capacity(records.len() + 1);
    let mut leaf_chunks: Vec<&[u8]> = Vec::with_capacity(records.len() * 2 + 1);
    let mut receipt_chunks: Vec<&[u8]> = Vec::with_capacity(records.len() * 2 + 1);
    let mut frontier_chunks: Vec<&[u8]> = Vec::with_capacity(records.len() + 1);
    let mut history_chunks: Vec<&[u8]> = Vec::with_capacity(records.len() + 1);

    let record_count = (records.len() as u32).to_le_bytes();
    tx_statements.push(&record_count);
    leaf_chunks.push(&record_count);
    receipt_chunks.push(&record_count);
    frontier_chunks.push(&record_count);
    history_chunks.push(&record_count);

    let mut previous_index = None;
    for record in records {
        if previous_index.map_or(false, |prev| record.tx_index != prev + 1) {
            return Err(BlockRecursionError::InvalidField(
                "verified leaf records must be ordered by tx_index",
            ));
        }
        previous_index = Some(record.tx_index);
        tx_statements.push(&record.tx_statement_commitment);
        leaf_chunks.push(&record.verified_leaf_commitment);
        receipt_chunks.push(&record.verified_receipt_commitment);
        frontier_chunks.push(&record.start_shielded_root);
        frontier_chunks.push(&record.end_shielded_root);
        history_chunks.push(&record.start_kernel_root);
        history_chunks.push(&record.end_kernel_root);
    }

    let tx_statements_commitment = fold_digest48(b"block_public_tx_statements", &tx_statements);
    let verified_leaf_commitment = fold_digest48(b"block_public_leaf_commitment", &leaf_chunks);
    let verified_receipt_commitment =
        fold_digest48(b"block_public_receipt_commitment", &receipt_chunks);
    let frontier_commitment = fold_digest32(b"block_public_frontier", &frontier_chunks);
    let history_commitment = fold_digest32(b"block_public_history", &history_chunks);

    let start_shielded_root = records.first().map(|r| r.start_shielded_root).unwrap_or([0; 32]);
    let end_shielded_root = records.last().map(|r| r.end_shielded_root).unwrap_or([0; 32]);
    let start_kernel_root = records.first().map(|r| r.start_kernel_root).unwrap_or([0; 32]);
    let end_kernel_root = records.last().map(|r| r.end_kernel_root).unwrap_or([0; 32]);
    let nullifier_root = records.last().map(|r| r.nullifier_root).unwrap_or([0; 32]);
    let da_root = records.last().map(|r| r.da_root).unwrap_or([0; 32]);

    Ok(RecursiveBlockPublicV1 {
        tx_count: records.len() as u32,
        tx_statements_commitment,
        verified_leaf_commitment,
        verified_receipt_commitment,
        start_shielded_root,
        end_shielded_root,
        start_kernel_root,
        end_kernel_root,
        nullifier_root,
        da_root,
        frontier_commitment,
        history_commitment,
    })
}
