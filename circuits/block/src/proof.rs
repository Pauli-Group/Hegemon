use protocol_versioning::{VersionBinding, VersionMatrix};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use state_merkle::CommitmentTree;
use transaction_circuit::{
    hashing::{felt_to_bytes32, merkle_node_bytes, Commitment, Felt},
    proof, TransactionProof, VerifyingKey,
};

use crate::error::BlockError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveAggregation {
    #[serde(with = "crate::proof::serde_bytes32")]
    pub digest: Commitment,
    pub transaction_count: usize,
}

impl RecursiveAggregation {
    pub fn new(digest: Commitment, transaction_count: usize) -> Self {
        Self {
            digest,
            transaction_count,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockProof {
    #[serde(with = "crate::proof::serde_bytes32")]
    pub starting_root: Commitment,
    #[serde(with = "crate::proof::serde_bytes32")]
    pub ending_root: Commitment,
    #[serde(with = "crate::proof::serde_vec_bytes32")]
    pub root_trace: Vec<Commitment>,
    pub aggregation: RecursiveAggregation,
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
    let starting_root = tree.root();
    let execution = execute_block(tree, transactions, verifying_keys)?;
    Ok(BlockProof {
        starting_root,
        ending_root: execution.ending_root,
        root_trace: execution.root_trace,
        aggregation: execution.aggregation,
        transactions: transactions.to_vec(),
        version_counts: serialize_version_counts(&execution.version_matrix),
    })
}

pub fn verify_block(
    tree: &mut CommitmentTree,
    proof: &BlockProof,
    verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
) -> Result<BlockVerificationReport, BlockError> {
    let observed_start = tree.root();
    if observed_start != proof.starting_root {
        return Err(BlockError::StartingRootMismatch {
            expected: proof.starting_root,
            observed: observed_start,
        });
    }
    let execution = execute_block(tree, &proof.transactions, verifying_keys)?;
    if execution.root_trace != proof.root_trace {
        return Err(BlockError::RootTraceMismatch);
    }
    if execution.ending_root != proof.ending_root
        || execution.aggregation.digest != proof.aggregation.digest
        || execution.aggregation.transaction_count != proof.aggregation.transaction_count
    {
        return Err(BlockError::AggregationMismatch);
    }
    if !version_counts_match(&proof.version_counts, &execution.version_matrix) {
        return Err(BlockError::VersionMatrixMismatch);
    }
    Ok(BlockVerificationReport { verified: true })
}

type ExecutionResult = ExecutionArtifacts;

struct ExecutionArtifacts {
    root_trace: Vec<Commitment>,
    ending_root: Commitment,
    aggregation: RecursiveAggregation,
    version_matrix: VersionMatrix,
}

fn execute_block(
    tree: &mut CommitmentTree,
    transactions: &[TransactionProof],
    verifying_keys: &HashMap<VersionBinding, VerifyingKey>,
) -> Result<ExecutionResult, BlockError> {
    let mut root_trace = Vec::with_capacity(transactions.len() + 1);
    root_trace.push(tree.root());
    let mut seen_nullifiers: HashSet<[u8; 32]> = HashSet::new();
    let mut digest = [0u8; 32];
    let zero = [0u8; 32];
    let mut version_matrix = VersionMatrix::new();

    for (index, proof) in transactions.iter().enumerate() {
        let binding = proof.version_binding();
        let verifying_key = verifying_keys
            .get(&binding)
            .ok_or(BlockError::UnsupportedVersion {
                index,
                version: binding,
            })?;
        let report = proof::verify(proof, verifying_key)
            .map_err(|source| BlockError::TransactionVerification { index, source })?;
        if !report.verified {
            return Err(BlockError::TransactionRejected(index));
        }
        let expected_root = *root_trace.last().expect("trace has prior root");
        if proof.public_inputs.merkle_root != expected_root {
            return Err(BlockError::UnexpectedMerkleRoot {
                index,
                expected: expected_root,
                reported: proof.public_inputs.merkle_root,
            });
        }

        for &nullifier in &proof.nullifiers {
            if nullifier == zero {
                continue;
            }
            if !seen_nullifiers.insert(nullifier) {
                return Err(BlockError::DuplicateNullifier(nullifier));
            }
        }

        for &commitment in proof.commitments.iter().filter(|c| **c != zero) {
            tree.append(commitment)?;
        }

        root_trace.push(tree.root());
        digest = fold_digest(digest, proof);
        version_matrix.observe(binding);
    }

    Ok(ExecutionArtifacts {
        root_trace,
        ending_root: tree.root(),
        aggregation: RecursiveAggregation::new(digest, transactions.len()),
        version_matrix,
    })
}

fn fold_digest(mut acc: Commitment, proof: &TransactionProof) -> Commitment {
    let binding = proof.version_binding();
    acc = merkle_node_bytes(
        &acc,
        &felt_to_bytes32(Felt::new(u64::from(binding.circuit))),
    )
    .expect("canonical digest bytes");
    acc = merkle_node_bytes(&acc, &felt_to_bytes32(Felt::new(u64::from(binding.crypto))))
        .expect("canonical digest bytes");
    acc =
        merkle_node_bytes(&acc, &proof.public_inputs.merkle_root).expect("canonical digest bytes");
    acc = merkle_node_bytes(&acc, &felt_to_bytes32(proof.public_inputs.balance_tag))
        .expect("canonical digest bytes");
    for value in &proof.public_inputs.nullifiers {
        acc = merkle_node_bytes(&acc, value).expect("canonical digest bytes");
    }
    for value in &proof.public_inputs.commitments {
        acc = merkle_node_bytes(&acc, value).expect("canonical digest bytes");
    }
    acc = merkle_node_bytes(
        &acc,
        &felt_to_bytes32(Felt::new(proof.public_inputs.native_fee)),
    )
    .expect("canonical digest bytes");
    acc
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

mod serde_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod serde_vec_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(values: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(values.len() * 32);
        for value in values {
            bytes.extend_from_slice(value);
        }
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if !bytes.len().is_multiple_of(32) {
            return Err(serde::de::Error::custom("invalid 32-byte encoding"));
        }
        Ok(bytes
            .chunks(32)
            .map(|chunk| <[u8; 32]>::try_from(chunk).expect("32-byte chunk"))
            .collect())
    }
}
