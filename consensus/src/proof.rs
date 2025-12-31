use crate::error::ProofError;
use crate::types::{
    Block, FeeCommitment, RecursiveProofHash, StarkCommitment, VersionCommitment,
    compute_fee_commitment, compute_proof_commitment, compute_version_commitment,
};
use block_circuit::{transaction_inputs_from_verifier_inputs, verify_recursive_proof};
use transaction_circuit::hashing::felts_to_bytes32;

pub trait ProofVerifier: Send + Sync {
    fn verify_block<BH>(&self, block: &Block<BH>) -> Result<(), ProofError>
    where
        BH: HeaderProofExt;
}

#[derive(Clone, Debug, Default)]
pub struct HashVerifier;

impl ProofVerifier for HashVerifier {
    fn verify_block<BH>(&self, block: &Block<BH>) -> Result<(), ProofError>
    where
        BH: HeaderProofExt,
    {
        verify_commitments(block)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecursiveProofVerifier;

impl ProofVerifier for RecursiveProofVerifier {
    fn verify_block<BH>(&self, block: &Block<BH>) -> Result<(), ProofError>
    where
        BH: HeaderProofExt,
    {
        verify_recursive_proof_payload(block)
    }
}

pub trait HeaderProofExt {
    fn proof_commitment(&self) -> StarkCommitment;
    fn fee_commitment(&self) -> FeeCommitment;
    fn transaction_count(&self) -> u32;
    fn version_commitment(&self) -> VersionCommitment;
    fn recursive_proof_hash(&self) -> RecursiveProofHash;
}

impl HeaderProofExt for crate::header::BlockHeader {
    fn proof_commitment(&self) -> StarkCommitment {
        self.proof_commitment
    }

    fn fee_commitment(&self) -> FeeCommitment {
        self.fee_commitment
    }

    fn transaction_count(&self) -> u32 {
        self.tx_count
    }

    fn version_commitment(&self) -> VersionCommitment {
        self.version_commitment
    }

    fn recursive_proof_hash(&self) -> RecursiveProofHash {
        self.recursive_proof_hash
    }
}

pub fn verify_commitments<BH>(block: &Block<BH>) -> Result<(), ProofError>
where
    BH: HeaderProofExt,
{
    let computed_proof = compute_proof_commitment(&block.transactions);
    if computed_proof != block.header.proof_commitment() {
        return Err(ProofError::CommitmentMismatch);
    }
    if block.transactions.len() as u32 != block.header.transaction_count() {
        return Err(ProofError::TransactionCount);
    }
    let computed_fee = compute_fee_commitment(&block.transactions);
    if computed_fee != block.header.fee_commitment() {
        return Err(ProofError::FeeCommitment);
    }
    let computed_versions = compute_version_commitment(&block.transactions);
    if computed_versions != block.header.version_commitment() {
        return Err(ProofError::VersionCommitment);
    }
    Ok(())
}

pub fn verify_recursive_proof_payload<BH>(block: &Block<BH>) -> Result<(), ProofError>
where
    BH: HeaderProofExt,
{
    let header_hash = block.header.recursive_proof_hash();
    if header_hash == [0u8; 32] {
        if block.recursive_proof.is_some() {
            return Err(ProofError::UnexpectedRecursiveProof);
        }
        return Ok(());
    }

    let proof = block
        .recursive_proof
        .as_ref()
        .ok_or(ProofError::MissingRecursiveProof)?;
    if proof.recursive_proof_hash != header_hash {
        return Err(ProofError::RecursiveProofHashMismatch);
    }
    if proof.tx_count != block.header.transaction_count() {
        return Err(ProofError::RecursiveProofCountMismatch);
    }
    if proof.tx_count as usize != block.transactions.len() {
        return Err(ProofError::RecursiveProofCountMismatch);
    }

    let verifier_inputs =
        verify_recursive_proof(proof).map_err(|err| map_block_error(err))?;
    if verifier_inputs.len() < block.transactions.len() || !verifier_inputs.len().is_power_of_two()
    {
        return Err(ProofError::RecursiveProofCountMismatch);
    }
    if verifier_inputs.len() != block.transactions.len() {
        let tx_count = block.transactions.len();
        if tx_count == 0 || verifier_inputs.is_empty() {
            return Err(ProofError::RecursiveProofPaddingMismatch);
        }
        let last = &verifier_inputs[tx_count - 1];
        let padding_ok = verifier_inputs[tx_count..].iter().all(|entry| {
            entry.inner_public_inputs == last.inner_public_inputs
                && entry.inner_pub_inputs_hash == last.inner_pub_inputs_hash
                && entry.trace_commitment == last.trace_commitment
                && entry.constraint_commitment == last.constraint_commitment
                && entry.fri_commitments == last.fri_commitments
                && entry.num_queries == last.num_queries
                && entry.num_draws == last.num_draws
                && entry.trace_partition_size == last.trace_partition_size
                && entry.constraint_partition_size == last.constraint_partition_size
                && entry.blowup_factor == last.blowup_factor
                && entry.trace_length == last.trace_length
                && entry.trace_width == last.trace_width
                && entry.constraint_frame_width == last.constraint_frame_width
                && entry.num_transition_constraints == last.num_transition_constraints
                && entry.num_assertions == last.num_assertions
                && entry.field_extension == last.field_extension
        });
        if !padding_ok {
            return Err(ProofError::RecursiveProofPaddingMismatch);
        }
    }

    for (index, tx) in block.transactions.iter().enumerate() {
        let inner = transaction_inputs_from_verifier_inputs(&verifier_inputs[index])
            .map_err(map_block_error)?;
        let expected_nullifiers: Vec<[u8; 32]> = inner
            .nullifiers
            .iter()
            .map(felts_to_bytes32)
            .filter(|value| *value != [0u8; 32])
            .collect();
        let expected_commitments: Vec<[u8; 32]> = inner
            .commitments
            .iter()
            .map(felts_to_bytes32)
            .filter(|value| *value != [0u8; 32])
            .collect();

        if expected_nullifiers != tx.nullifiers || expected_commitments != tx.commitments {
            return Err(ProofError::RecursiveProofInputsMismatch(index));
        }
    }

    Ok(())
}

fn map_block_error(err: block_circuit::BlockError) -> ProofError {
    match err {
        block_circuit::BlockError::RecursiveProofHashMismatch => {
            ProofError::RecursiveProofHashMismatch
        }
        block_circuit::BlockError::RecursiveProofVerification(message) => {
            ProofError::RecursiveProofVerification(message)
        }
        block_circuit::BlockError::RecursiveProofCountMismatch => {
            ProofError::RecursiveProofCountMismatch
        }
        block_circuit::BlockError::RecursiveProofPaddingMismatch => {
            ProofError::RecursiveProofPaddingMismatch
        }
        block_circuit::BlockError::RecursiveProofInputsMismatch(index) => {
            ProofError::RecursiveProofInputsMismatch(index)
        }
        other => ProofError::RecursiveProofVerification(other.to_string()),
    }
}
