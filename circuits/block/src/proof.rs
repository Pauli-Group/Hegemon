use protocol_versioning::{VersionBinding, VersionMatrix};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use state_merkle::CommitmentTree;
use transaction_circuit::{TransactionProof, VerifyingKey};

use crate::error::BlockError;
use crate::recursive::{
    prove_block_recursive, prove_block_recursive_fast, verify_block_recursive, RecursiveBlockProof,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockProof {
    pub recursive_proof: RecursiveBlockProof,
    pub transactions: Vec<TransactionProof>,
    pub version_counts: Vec<VersionCount>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionCount {
    pub version: VersionBinding,
    pub count: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockVerificationReport {
    pub verified: bool,
}

pub fn prove_block(
    tree: &mut CommitmentTree,
    transactions: &[TransactionProof],
    verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
) -> Result<BlockProof, BlockError> {
    let recursive_proof = prove_block_recursive(tree, transactions, verifying_keys)?;
    let version_matrix = observe_versions(transactions);
    Ok(BlockProof {
        recursive_proof,
        transactions: transactions.to_vec(),
        version_counts: serialize_version_counts(&version_matrix),
    })
}

/// Produce a recursive block proof using fast, lower-soundness options.
pub fn prove_block_fast(
    tree: &mut CommitmentTree,
    transactions: &[TransactionProof],
    verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
) -> Result<BlockProof, BlockError> {
    let recursive_proof = prove_block_recursive_fast(tree, transactions, verifying_keys)?;
    let version_matrix = observe_versions(transactions);
    Ok(BlockProof {
        recursive_proof,
        transactions: transactions.to_vec(),
        version_counts: serialize_version_counts(&version_matrix),
    })
}

pub fn verify_block(
    tree: &mut CommitmentTree,
    proof: &BlockProof,
    verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
) -> Result<BlockVerificationReport, BlockError> {
    verify_block_recursive(
        tree,
        &proof.recursive_proof,
        &proof.transactions,
        verifying_keys,
    )?;
    let version_matrix = observe_versions(&proof.transactions);
    if !version_counts_match(&proof.version_counts, &version_matrix) {
        return Err(BlockError::VersionMatrixMismatch);
    }
    Ok(BlockVerificationReport { verified: true })
}

fn observe_versions(transactions: &[TransactionProof]) -> VersionMatrix {
    let mut matrix = VersionMatrix::new();
    for proof in transactions {
        matrix.observe(proof.version_binding());
    }
    matrix
}

fn serialize_version_counts(matrix: &VersionMatrix) -> Vec<VersionCount> {
    matrix
        .counts()
        .iter()
        .map(|(version, count)| VersionCount {
            version: *version,
            count: *count,
        })
        .collect()
}

fn version_counts_match(counts: &[VersionCount], execution: &VersionMatrix) -> bool {
    let reported =
        VersionMatrix::from_counts(counts.iter().map(|entry| (entry.version, entry.count)));
    reported.counts() == execution.counts()
}
