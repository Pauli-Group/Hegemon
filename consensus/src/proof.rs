use crate::commitment_tree::CommitmentTreeState;
use crate::error::ProofError;
use crate::types::{
    Block, DaParams, DaRoot, FeeCommitment, StarkCommitment, VersionCommitment,
    compute_fee_commitment, compute_proof_commitment, compute_version_commitment, da_root,
};
use block_circuit::{CommitmentBlockProof, CommitmentBlockProver, verify_block_commitment};
#[cfg(feature = "legacy-recursion")]
use block_circuit::{transaction_inputs_from_verifier_inputs, verify_recursive_proof};
use crypto::hashes::blake3_384;
use rayon::prelude::*;
use std::collections::BTreeSet;
use transaction_circuit::constants::MAX_INPUTS;
use transaction_circuit::hashing_pq::felts_to_bytes48;
use transaction_circuit::keys::generate_keys;
use transaction_circuit::proof::verify as verify_transaction_proof;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentNullifierLists {
    pub nullifiers: Vec<[u8; 48]>,
    pub sorted_nullifiers: Vec<[u8; 48]>,
}

pub fn commitment_nullifier_lists(
    transactions: &[crate::types::Transaction],
) -> Result<CommitmentNullifierLists, ProofError> {
    if transactions.is_empty() {
        return Err(ProofError::CommitmentProofEmptyBlock);
    }

    let mut nullifiers = Vec::with_capacity(transactions.len().saturating_mul(MAX_INPUTS));
    for (index, tx) in transactions.iter().enumerate() {
        if tx.nullifiers.len() > MAX_INPUTS {
            return Err(ProofError::CommitmentProofInputsMismatch(format!(
                "transaction {index} nullifier length {} exceeds MAX_INPUTS {MAX_INPUTS}",
                tx.nullifiers.len()
            )));
        }
        if tx.nullifiers.contains(&[0u8; 48]) {
            return Err(ProofError::CommitmentProofInputsMismatch(format!(
                "transaction {index} includes zero nullifier"
            )));
        }
        nullifiers.extend_from_slice(&tx.nullifiers);
        nullifiers.extend(std::iter::repeat_n(
            [0u8; 48],
            MAX_INPUTS - tx.nullifiers.len(),
        ));
    }

    if nullifiers.iter().all(|nf| *nf == [0u8; 48]) {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "nullifier list must include at least one non-zero entry".to_string(),
        ));
    }

    let mut sorted_nullifiers = nullifiers.clone();
    sorted_nullifiers.sort_unstable();

    Ok(CommitmentNullifierLists {
        nullifiers,
        sorted_nullifiers,
    })
}

pub fn verify_commitment_proof_payload(
    block: &Block<impl HeaderProofExt>,
    parent_commitment_tree: &CommitmentTreeState,
    proof: &CommitmentBlockProof,
) -> Result<(), ProofError> {
    let lists = commitment_nullifier_lists(&block.transactions)?;

    if proof.public_inputs.tx_count as usize != block.transactions.len() {
        return Err(ProofError::CommitmentProofInputsMismatch(format!(
            "tx_count mismatch (proof {}, block {})",
            proof.public_inputs.tx_count,
            block.transactions.len()
        )));
    }

    let proof_nullifiers: Vec<[u8; 48]> = proof
        .public_inputs
        .nullifiers
        .iter()
        .map(felts_to_bytes48)
        .collect();
    if proof_nullifiers != lists.nullifiers {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "nullifier list mismatch".to_string(),
        ));
    }
    let proof_sorted_nullifiers: Vec<[u8; 48]> = proof
        .public_inputs
        .sorted_nullifiers
        .iter()
        .map(felts_to_bytes48)
        .collect();
    if proof_sorted_nullifiers != lists.sorted_nullifiers {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "sorted nullifier list mismatch".to_string(),
        ));
    }

    let expected_da_root = da_root(&block.transactions, block.header.da_params())
        .map_err(|err| ProofError::DaEncoding(err.to_string()))?;
    let proof_da_root = felts_to_bytes48(&proof.public_inputs.da_root);
    if proof_da_root != expected_da_root {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "da_root mismatch".to_string(),
        ));
    }

    let expected_nullifier_root = nullifier_root_from_list(&lists.nullifiers)?;
    let proof_nullifier_root = felts_to_bytes48(&proof.public_inputs.nullifier_root);
    if proof_nullifier_root != expected_nullifier_root {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "nullifier root mismatch".to_string(),
        ));
    }

    let proof_starting_root = felts_to_bytes48(&proof.public_inputs.starting_state_root);
    if proof_starting_root != parent_commitment_tree.root() {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "starting state root mismatch".to_string(),
        ));
    }
    let expected_tree = apply_commitments(parent_commitment_tree, &block.transactions)?;
    let proof_ending_root = felts_to_bytes48(&proof.public_inputs.ending_state_root);
    if proof_ending_root != expected_tree.root() {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "ending state root mismatch".to_string(),
        ));
    }

    verify_block_commitment(proof)
        .map_err(|err| ProofError::CommitmentProofVerification(err.to_string()))?;
    Ok(())
}

pub trait ProofVerifier: Send + Sync {
    fn verify_block<BH>(
        &self,
        block: &Block<BH>,
        parent_commitment_tree: &CommitmentTreeState,
    ) -> Result<CommitmentTreeState, ProofError>
    where
        BH: HeaderProofExt;
}

#[derive(Clone, Debug, Default)]
pub struct HashVerifier;

impl ProofVerifier for HashVerifier {
    fn verify_block<BH>(
        &self,
        block: &Block<BH>,
        parent_commitment_tree: &CommitmentTreeState,
    ) -> Result<CommitmentTreeState, ProofError>
    where
        BH: HeaderProofExt,
    {
        verify_commitments(block)?;
        apply_commitments(parent_commitment_tree, &block.transactions)
    }
}

#[cfg(feature = "legacy-recursion")]
#[derive(Clone, Debug, Default)]
pub struct RecursiveProofVerifier;

#[cfg(feature = "legacy-recursion")]
impl ProofVerifier for RecursiveProofVerifier {
    fn verify_block<BH>(
        &self,
        block: &Block<BH>,
        parent_commitment_tree: &CommitmentTreeState,
    ) -> Result<CommitmentTreeState, ProofError>
    where
        BH: HeaderProofExt,
    {
        verify_recursive_proof_payload(block, parent_commitment_tree)
    }
}

#[derive(Clone, Debug)]
pub struct ParallelProofVerifier {
    verifying_key: transaction_circuit::keys::VerifyingKey,
}

impl ParallelProofVerifier {
    pub fn new() -> Self {
        let (_, verifying_key) = generate_keys();
        Self { verifying_key }
    }
}

impl Default for ParallelProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofVerifier for ParallelProofVerifier {
    fn verify_block<BH>(
        &self,
        block: &Block<BH>,
        parent_commitment_tree: &CommitmentTreeState,
    ) -> Result<CommitmentTreeState, ProofError>
    where
        BH: HeaderProofExt,
    {
        if block.transactions.is_empty() {
            if block.commitment_proof.is_some() || block.transaction_proofs.is_some() {
                return Err(ProofError::CommitmentProofEmptyBlock);
            }
            return apply_commitments(parent_commitment_tree, &block.transactions);
        }

        let commitment_proof = block
            .commitment_proof
            .as_ref()
            .ok_or(ProofError::MissingCommitmentProof)?;
        let transaction_proofs = block
            .transaction_proofs
            .as_ref()
            .ok_or(ProofError::MissingTransactionProofs)?;
        if transaction_proofs.len() != block.transactions.len() {
            return Err(ProofError::TransactionProofCountMismatch {
                expected: block.transactions.len(),
                observed: transaction_proofs.len(),
            });
        }

        verify_commitment_proof_payload(block, parent_commitment_tree, commitment_proof)?;

        let proof_hashes = proof_hashes_from_transaction_proofs(transaction_proofs)?;
        let expected_commitment =
            CommitmentBlockProver::commitment_from_proof_hashes(&proof_hashes)
                .map_err(|err| ProofError::CommitmentProofInputsMismatch(err.to_string()))?;
        let proof_commitment =
            felts_to_bytes48(&commitment_proof.public_inputs.tx_proofs_commitment);
        if expected_commitment != proof_commitment {
            return Err(ProofError::CommitmentProofInputsMismatch(
                "tx_proofs_commitment mismatch".to_string(),
            ));
        }

        transaction_proofs
            .par_iter()
            .zip(&block.transactions)
            .enumerate()
            .try_for_each(|(index, (proof, tx))| {
                verify_transaction_proof_inputs(index, tx, proof)?;
                verify_transaction_proof(proof, &self.verifying_key).map_err(|err| {
                    ProofError::TransactionProofVerification {
                        index,
                        message: err.to_string(),
                    }
                })?;
                Ok::<_, ProofError>(())
            })?;

        let anchors: Vec<[u8; 48]> = transaction_proofs
            .iter()
            .map(|proof| proof.public_inputs.merkle_root)
            .collect();

        let proof_starting_root =
            felts_to_bytes48(&commitment_proof.public_inputs.starting_state_root);
        let proof_ending_root =
            felts_to_bytes48(&commitment_proof.public_inputs.ending_state_root);
        verify_and_apply_tree_transition(
            parent_commitment_tree,
            proof_starting_root,
            proof_ending_root,
            &block.transactions,
            &anchors,
        )
    }
}

pub trait HeaderProofExt {
    fn proof_commitment(&self) -> StarkCommitment;
    fn fee_commitment(&self) -> FeeCommitment;
    fn transaction_count(&self) -> u32;
    fn version_commitment(&self) -> VersionCommitment;
    fn da_root(&self) -> DaRoot;
    fn da_params(&self) -> DaParams;
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

    fn da_root(&self) -> DaRoot {
        self.da_root
    }

    fn da_params(&self) -> DaParams {
        self.da_params
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
    let computed_da_root = da_root(&block.transactions, block.header.da_params())
        .map_err(|err| ProofError::DaEncoding(err.to_string()))?;
    if computed_da_root != block.header.da_root() {
        return Err(ProofError::DaRootMismatch);
    }
    Ok(())
}

#[cfg(feature = "legacy-recursion")]
pub fn verify_recursive_proof_payload<BH>(
    block: &Block<BH>,
    parent_commitment_tree: &CommitmentTreeState,
) -> Result<CommitmentTreeState, ProofError>
where
    BH: HeaderProofExt,
{
    let proof = match block.recursive_proof.as_ref() {
        Some(proof) => proof,
        None => return apply_commitments(parent_commitment_tree, &block.transactions),
    };
    if block.transactions.is_empty() {
        return Err(ProofError::UnexpectedRecursiveProof);
    }
    if proof.tx_count != block.header.transaction_count() {
        return Err(ProofError::RecursiveProofCountMismatch);
    }
    if proof.tx_count as usize != block.transactions.len() {
        return Err(ProofError::RecursiveProofCountMismatch);
    }

    let verifier_inputs = verify_recursive_proof(proof).map_err(|err| map_block_error(err))?;
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

    let mut anchors = Vec::with_capacity(block.transactions.len());
    for (index, tx) in block.transactions.iter().enumerate() {
        let inner = transaction_inputs_from_verifier_inputs(&verifier_inputs[index])
            .map_err(map_block_error)?;
        anchors.push(felts_to_bytes48(&inner.merkle_root));
        let expected_nullifiers: Vec<[u8; 48]> = inner
            .nullifiers
            .iter()
            .map(felts_to_bytes48)
            .filter(|value| *value != [0u8; 48])
            .collect();
        let expected_commitments: Vec<[u8; 48]> = inner
            .commitments
            .iter()
            .map(felts_to_bytes48)
            .filter(|value| *value != [0u8; 48])
            .collect();

        if expected_nullifiers != tx.nullifiers || expected_commitments != tx.commitments {
            return Err(ProofError::RecursiveProofInputsMismatch(index));
        }
    }
    verify_and_apply_tree_transition(
        parent_commitment_tree,
        proof.starting_root,
        proof.ending_root,
        &block.transactions,
        &anchors,
    )
}

#[cfg(feature = "legacy-recursion")]
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

fn apply_commitments(
    parent_commitment_tree: &CommitmentTreeState,
    transactions: &[crate::types::Transaction],
) -> Result<CommitmentTreeState, ProofError> {
    let mut tree = parent_commitment_tree.clone();
    for tx in transactions {
        for commitment in tx.commitments.iter().copied().filter(|c| *c != [0u8; 48]) {
            tree.append(commitment)?;
        }
    }
    Ok(tree)
}

fn proof_hashes_from_transaction_proofs(
    proofs: &[transaction_circuit::TransactionProof],
) -> Result<Vec<[u8; 48]>, ProofError> {
    let mut hashes = Vec::with_capacity(proofs.len());
    for (index, proof) in proofs.iter().enumerate() {
        if proof.stark_proof.is_empty() {
            return Err(ProofError::TransactionProofInputsMismatch {
                index,
                message: "missing STARK proof bytes".to_string(),
            });
        }
        hashes.push(blake3_384(&proof.stark_proof));
    }
    Ok(hashes)
}

fn verify_transaction_proof_inputs(
    index: usize,
    tx: &crate::types::Transaction,
    proof: &transaction_circuit::TransactionProof,
) -> Result<(), ProofError> {
    if proof.version_binding() != tx.version {
        return Err(ProofError::TransactionProofInputsMismatch {
            index,
            message: "version binding mismatch".to_string(),
        });
    }

    let expected_nullifiers: Vec<[u8; 48]> = proof
        .nullifiers
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 48])
        .collect();
    if expected_nullifiers != tx.nullifiers {
        return Err(ProofError::TransactionProofInputsMismatch {
            index,
            message: "nullifier list mismatch".to_string(),
        });
    }

    let expected_commitments: Vec<[u8; 48]> = proof
        .commitments
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 48])
        .collect();
    if expected_commitments != tx.commitments {
        return Err(ProofError::TransactionProofInputsMismatch {
            index,
            message: "commitment list mismatch".to_string(),
        });
    }

    if proof.public_inputs.balance_tag != tx.balance_tag {
        return Err(ProofError::TransactionProofInputsMismatch {
            index,
            message: "balance tag mismatch".to_string(),
        });
    }

    Ok(())
}

fn nullifier_root_from_list(nullifiers: &[[u8; 48]]) -> Result<[u8; 48], ProofError> {
    let mut entries = BTreeSet::new();
    for nf in nullifiers {
        if *nf == [0u8; 48] {
            continue;
        }
        if !entries.insert(*nf) {
            return Err(ProofError::CommitmentProofInputsMismatch(
                "duplicate nullifier in block".to_string(),
            ));
        }
    }

    let mut data = Vec::with_capacity(entries.len() * 48);
    for nf in entries {
        data.extend_from_slice(&nf);
    }

    Ok(blake3_384(&data))
}

fn verify_and_apply_tree_transition(
    parent_commitment_tree: &CommitmentTreeState,
    proof_starting_root: [u8; 48],
    proof_ending_root: [u8; 48],
    transactions: &[crate::types::Transaction],
    anchors: &[[u8; 48]],
) -> Result<CommitmentTreeState, ProofError> {
    if anchors.len() != transactions.len() {
        return Err(ProofError::Internal("anchor list length mismatch"));
    }

    let mut tree = parent_commitment_tree.clone();
    if proof_starting_root != tree.root() {
        return Err(ProofError::StartingRootMismatch {
            expected: tree.root(),
            observed: proof_starting_root,
        });
    }

    for (index, (tx, anchor)) in transactions.iter().zip(anchors).enumerate() {
        if !tree.contains_root(anchor) {
            return Err(ProofError::InvalidAnchor {
                index,
                anchor: *anchor,
            });
        }
        for commitment in tx.commitments.iter().copied().filter(|c| *c != [0u8; 48]) {
            tree.append(commitment)?;
        }
    }

    if proof_ending_root != tree.root() {
        return Err(ProofError::EndingRootMismatch {
            expected: tree.root(),
            observed: proof_ending_root,
        });
    }

    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_versioning::DEFAULT_VERSION_BINDING;

    fn tx_with_commitments(commitments: Vec<[u8; 48]>) -> crate::types::Transaction {
        crate::types::Transaction::new(
            Vec::new(),
            commitments,
            [42u8; 48],
            DEFAULT_VERSION_BINDING,
            Vec::new(),
        )
    }

    #[test]
    fn tree_transition_rejects_starting_root_mismatch() {
        let parent_tree = CommitmentTreeState::default();
        let txs = vec![tx_with_commitments(vec![[1u8; 48]])];
        let anchors = vec![parent_tree.root()];
        let err = verify_and_apply_tree_transition(
            &parent_tree,
            [9u8; 48],
            parent_tree.root(),
            &txs,
            &anchors,
        )
        .expect_err("starting root mismatch");
        assert!(matches!(err, ProofError::StartingRootMismatch { .. }));
    }

    #[test]
    fn tree_transition_rejects_invalid_anchor() {
        let parent_tree = CommitmentTreeState::default();
        let txs = vec![tx_with_commitments(vec![[1u8; 48]])];
        let anchors = vec![[7u8; 48]];
        let err = verify_and_apply_tree_transition(
            &parent_tree,
            parent_tree.root(),
            parent_tree.root(),
            &txs,
            &anchors,
        )
        .expect_err("invalid anchor");
        assert!(matches!(err, ProofError::InvalidAnchor { .. }));
    }

    #[test]
    fn tree_transition_rejects_ending_root_mismatch() {
        let parent_tree = CommitmentTreeState::default();
        let txs = vec![tx_with_commitments(vec![[1u8; 48]])];
        let anchors = vec![parent_tree.root()];
        let err = verify_and_apply_tree_transition(
            &parent_tree,
            parent_tree.root(),
            [9u8; 48],
            &txs,
            &anchors,
        )
        .expect_err("ending root mismatch");
        assert!(matches!(err, ProofError::EndingRootMismatch { .. }));
    }

    #[test]
    fn tree_transition_accepts_valid_update() {
        let parent_tree = CommitmentTreeState::default();
        let txs = vec![tx_with_commitments(vec![[1u8; 48]])];
        let anchors = vec![parent_tree.root()];
        let mut expected = parent_tree.clone();
        expected.append([1u8; 48]).expect("append");
        let updated = verify_and_apply_tree_transition(
            &parent_tree,
            parent_tree.root(),
            expected.root(),
            &txs,
            &anchors,
        )
        .expect("valid transition");
        assert_eq!(updated.root(), expected.root());
    }
}
