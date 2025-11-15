use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use state_merkle::CommitmentTree;
use transaction_circuit::{
    hashing::{merkle_node, Felt},
    proof, TransactionProof, VerifyingKey,
};

use crate::error::BlockError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveAggregation {
    #[serde(with = "crate::proof::serde_felt")]
    pub digest: Felt,
    pub transaction_count: usize,
}

impl RecursiveAggregation {
    pub fn new(digest: Felt, transaction_count: usize) -> Self {
        Self {
            digest,
            transaction_count,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockProof {
    #[serde(with = "crate::proof::serde_felt")]
    pub starting_root: Felt,
    #[serde(with = "crate::proof::serde_felt")]
    pub ending_root: Felt,
    #[serde(with = "crate::proof::serde_vec_felt")]
    pub root_trace: Vec<Felt>,
    pub aggregation: RecursiveAggregation,
    pub transactions: Vec<TransactionProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockVerificationReport {
    pub verified: bool,
}

pub fn prove_block(
    tree: &mut CommitmentTree,
    transactions: &[TransactionProof],
    verifying_key: &VerifyingKey,
) -> Result<BlockProof, BlockError> {
    let starting_root = tree.root();
    let execution = execute_block(tree, transactions, verifying_key)?;
    Ok(BlockProof {
        starting_root,
        ending_root: execution.ending_root,
        root_trace: execution.root_trace,
        aggregation: execution.aggregation,
        transactions: transactions.to_vec(),
    })
}

pub fn verify_block(
    tree: &mut CommitmentTree,
    proof: &BlockProof,
    verifying_key: &VerifyingKey,
) -> Result<BlockVerificationReport, BlockError> {
    let observed_start = tree.root();
    if observed_start != proof.starting_root {
        return Err(BlockError::StartingRootMismatch {
            expected: proof.starting_root,
            observed: observed_start,
        });
    }
    let execution = execute_block(tree, &proof.transactions, verifying_key)?;
    if execution.root_trace != proof.root_trace {
        return Err(BlockError::RootTraceMismatch);
    }
    if execution.ending_root != proof.ending_root
        || execution.aggregation.digest != proof.aggregation.digest
        || execution.aggregation.transaction_count != proof.aggregation.transaction_count
    {
        return Err(BlockError::AggregationMismatch);
    }
    Ok(BlockVerificationReport { verified: true })
}

type ExecutionResult = ExecutionArtifacts;

struct ExecutionArtifacts {
    root_trace: Vec<Felt>,
    ending_root: Felt,
    aggregation: RecursiveAggregation,
}

fn execute_block(
    tree: &mut CommitmentTree,
    transactions: &[TransactionProof],
    verifying_key: &VerifyingKey,
) -> Result<ExecutionResult, BlockError> {
    let mut root_trace = Vec::with_capacity(transactions.len() + 1);
    root_trace.push(tree.root());
    let mut seen_nullifiers: HashSet<u64> = HashSet::new();
    let mut digest = Felt::new(0);
    let zero = Felt::new(0);

    for (index, proof) in transactions.iter().enumerate() {
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
            if !seen_nullifiers.insert(nullifier.as_int()) {
                return Err(BlockError::DuplicateNullifier(nullifier));
            }
        }

        for &commitment in proof.commitments.iter().filter(|c| **c != zero) {
            tree.append(commitment)?;
        }

        root_trace.push(tree.root());
        digest = fold_digest(digest, proof);
    }

    Ok(ExecutionArtifacts {
        root_trace,
        ending_root: tree.root(),
        aggregation: RecursiveAggregation::new(digest, transactions.len()),
    })
}

fn fold_digest(mut acc: Felt, proof: &TransactionProof) -> Felt {
    acc = merkle_node(acc, proof.public_inputs.merkle_root);
    acc = merkle_node(acc, proof.public_inputs.balance_tag);
    for value in &proof.public_inputs.nullifiers {
        acc = merkle_node(acc, *value);
    }
    for value in &proof.public_inputs.commitments {
        acc = merkle_node(acc, *value);
    }
    acc = merkle_node(acc, Felt::new(proof.public_inputs.native_fee as u64));
    acc
}

mod serde_felt {
    use serde::{Deserialize, Deserializer, Serializer};
    use transaction_circuit::hashing::Felt;

    pub fn serialize<S>(value: &Felt, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(value.as_int())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Felt, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Ok(Felt::new(value))
    }
}

mod serde_vec_felt {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::convert::TryInto;
    use transaction_circuit::hashing::Felt;

    pub fn serialize<S>(values: &[Felt], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::with_capacity(values.len() * 8);
        for value in values {
            bytes.extend_from_slice(&value.as_int().to_be_bytes());
        }
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Felt>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if !bytes.len().is_multiple_of(8) {
            return Err(serde::de::Error::custom("invalid field encoding"));
        }
        Ok(bytes
            .chunks(8)
            .map(|chunk| {
                let array: [u8; 8] = chunk.try_into().expect("chunk size");
                Felt::new(u64::from_be_bytes(array))
            })
            .collect())
    }
}
