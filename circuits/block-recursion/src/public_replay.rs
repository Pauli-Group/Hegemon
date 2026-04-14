use crate::{
    fold_digest48,
    statement::{
        recursive_prefix_progress_tree_commitment_v1, recursive_prefix_statement_from_public_v1,
        recursive_segment_statement_from_prefixes_v1, RecursivePrefixStatementV1,
        RecursiveSegmentStatementV1,
    },
    BlockRecursionError, Digest32, Digest48,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockLeafRecordV1 {
    pub tx_index: u32,
    pub receipt_statement_hash: Digest48,
    pub receipt_proof_digest: Digest48,
    pub receipt_public_inputs_digest: Digest48,
    pub receipt_verifier_profile: Digest48,
    pub leaf_params_fingerprint: Digest48,
    pub leaf_spec_digest: Digest32,
    pub leaf_relation_id: Digest32,
    pub leaf_shape_digest: Digest32,
    pub leaf_statement_digest: Digest48,
    pub leaf_commitment_digest: Digest48,
    pub leaf_proof_digest: Digest48,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockSemanticInputsV1 {
    pub tx_statements_commitment: Digest48,
    pub start_shielded_root: Digest48,
    pub end_shielded_root: Digest48,
    pub start_kernel_root: Digest48,
    pub end_kernel_root: Digest48,
    pub nullifier_root: Digest48,
    pub da_root: Digest48,
    pub start_tree_commitment: Digest48,
    pub end_tree_commitment: Digest48,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveBlockPublicV1 {
    pub tx_count: u32,
    pub tx_statements_commitment: Digest48,
    pub verified_leaf_commitment: Digest48,
    pub verified_receipt_commitment: Digest48,
    pub start_shielded_root: Digest48,
    pub end_shielded_root: Digest48,
    pub start_kernel_root: Digest48,
    pub end_kernel_root: Digest48,
    pub nullifier_root: Digest48,
    pub da_root: Digest48,
    pub start_tree_commitment: Digest48,
    pub end_tree_commitment: Digest48,
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_fixed<const N: usize>(out: &mut Vec<u8>, value: &[u8; N]) {
    out.extend_from_slice(value);
}

pub fn canonical_receipt_record_bytes_v1(record: &BlockLeafRecordV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + (48 * 4));
    put_u32(&mut out, record.tx_index);
    put_fixed(&mut out, &record.receipt_statement_hash);
    put_fixed(&mut out, &record.receipt_proof_digest);
    put_fixed(&mut out, &record.receipt_public_inputs_digest);
    put_fixed(&mut out, &record.receipt_verifier_profile);
    out
}

pub fn canonical_verified_leaf_record_bytes_v1(record: &BlockLeafRecordV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + (48 * 7) + (32 * 3));
    put_u32(&mut out, record.tx_index);
    put_fixed(&mut out, &record.receipt_statement_hash);
    put_fixed(&mut out, &record.receipt_proof_digest);
    put_fixed(&mut out, &record.receipt_public_inputs_digest);
    put_fixed(&mut out, &record.receipt_verifier_profile);
    put_fixed(&mut out, &record.leaf_params_fingerprint);
    put_fixed(&mut out, &record.leaf_spec_digest);
    put_fixed(&mut out, &record.leaf_relation_id);
    put_fixed(&mut out, &record.leaf_shape_digest);
    put_fixed(&mut out, &record.leaf_statement_digest);
    put_fixed(&mut out, &record.leaf_commitment_digest);
    put_fixed(&mut out, &record.leaf_proof_digest);
    out
}

pub fn public_replay_v1(
    records: &[BlockLeafRecordV1],
    semantic: &BlockSemanticInputsV1,
) -> Result<RecursiveBlockPublicV1, BlockRecursionError> {
    let mut previous_index = None;
    let mut leaf_chunks: Vec<Vec<u8>> = Vec::with_capacity(records.len());
    let mut receipt_chunks: Vec<Vec<u8>> = Vec::with_capacity(records.len());
    for record in records {
        if previous_index.map_or(false, |prev| record.tx_index != prev + 1) {
            return Err(BlockRecursionError::InvalidField(
                "verified leaf records must be ordered by tx_index",
            ));
        }
        previous_index = Some(record.tx_index);
        leaf_chunks.push(canonical_verified_leaf_record_bytes_v1(record));
        receipt_chunks.push(canonical_receipt_record_bytes_v1(record));
    }

    let leaf_refs = leaf_chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let receipt_refs = receipt_chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();

    let (verified_leaf_commitment, verified_receipt_commitment) =
        fold_verified_record_commitments_v1(&leaf_refs, &receipt_refs);

    Ok(RecursiveBlockPublicV1 {
        tx_count: records.len() as u32,
        tx_statements_commitment: semantic.tx_statements_commitment,
        verified_leaf_commitment,
        verified_receipt_commitment,
        start_shielded_root: semantic.start_shielded_root,
        end_shielded_root: semantic.end_shielded_root,
        start_kernel_root: semantic.start_kernel_root,
        end_kernel_root: semantic.end_kernel_root,
        nullifier_root: semantic.nullifier_root,
        da_root: semantic.da_root,
        start_tree_commitment: semantic.start_tree_commitment,
        end_tree_commitment: semantic.end_tree_commitment,
    })
}

pub fn prefix_public_v1(
    records: &[BlockLeafRecordV1],
    semantic: &BlockSemanticInputsV1,
    terminal: bool,
) -> Result<RecursiveBlockPublicV1, BlockRecursionError> {
    let mut previous_index = None;
    let mut leaf_chunks: Vec<Vec<u8>> = Vec::with_capacity(records.len());
    let mut receipt_chunks: Vec<Vec<u8>> = Vec::with_capacity(records.len());
    for record in records {
        if previous_index.map_or(false, |prev| record.tx_index != prev + 1) {
            return Err(BlockRecursionError::InvalidField(
                "verified leaf records must be ordered by tx_index",
            ));
        }
        previous_index = Some(record.tx_index);
        leaf_chunks.push(canonical_verified_leaf_record_bytes_v1(record));
        receipt_chunks.push(canonical_receipt_record_bytes_v1(record));
    }

    let leaf_refs = leaf_chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let receipt_refs = receipt_chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let tx_count = records.len() as u32;
    let (verified_leaf_commitment, verified_receipt_commitment) =
        fold_verified_record_commitments_v1(&leaf_refs, &receipt_refs);
    let end_tree_commitment = if terminal {
        semantic.end_tree_commitment
    } else if tx_count == 0 {
        semantic.start_tree_commitment
    } else {
        recursive_prefix_progress_tree_commitment_v1(
            tx_count,
            semantic.start_tree_commitment,
            verified_leaf_commitment,
            verified_receipt_commitment,
        )
    };

    Ok(RecursiveBlockPublicV1 {
        tx_count,
        tx_statements_commitment: semantic.tx_statements_commitment,
        verified_leaf_commitment,
        verified_receipt_commitment,
        start_shielded_root: semantic.start_shielded_root,
        end_shielded_root: semantic.end_shielded_root,
        start_kernel_root: semantic.start_kernel_root,
        end_kernel_root: semantic.end_kernel_root,
        nullifier_root: semantic.nullifier_root,
        da_root: semantic.da_root,
        start_tree_commitment: semantic.start_tree_commitment,
        end_tree_commitment,
    })
}

pub fn prefix_statement_for_records_v1(
    records: &[BlockLeafRecordV1],
    semantic: &BlockSemanticInputsV1,
    terminal: bool,
) -> Result<RecursivePrefixStatementV1, BlockRecursionError> {
    let public = prefix_public_v1(records, semantic, terminal)?;
    Ok(recursive_prefix_statement_from_public_v1(&public))
}

pub fn segment_statement_for_interval_v1(
    records: &[BlockLeafRecordV1],
    semantic: &BlockSemanticInputsV1,
    start: usize,
    end: usize,
) -> Result<RecursiveSegmentStatementV1, BlockRecursionError> {
    if start > end {
        return Err(BlockRecursionError::ComposeCheckFailed(
            "segment interval start must be <= end",
        ));
    }
    if end > records.len() {
        return Err(BlockRecursionError::InvalidLength {
            what: "segment interval end",
            expected: records.len(),
            actual: end,
        });
    }

    let start_prefix =
        prefix_statement_for_records_v1(&records[..start], semantic, start == records.len())?;
    let end_prefix =
        prefix_statement_for_records_v1(&records[..end], semantic, end == records.len())?;
    recursive_segment_statement_from_prefixes_v1(&start_prefix, &end_prefix)
}

pub fn fold_verified_record_commitments_v1(
    leaf_refs: &[&[u8]],
    receipt_refs: &[&[u8]],
) -> (Digest48, Digest48) {
    let verified_leaf_commitment = fold_digest48(
        b"hegemon.block-recursion.verified-leaf-commitment.v1",
        leaf_refs,
    );
    let verified_receipt_commitment = fold_digest48(
        b"hegemon.block-recursion.verified-receipt-commitment.v1",
        receipt_refs,
    );
    (verified_leaf_commitment, verified_receipt_commitment)
}
