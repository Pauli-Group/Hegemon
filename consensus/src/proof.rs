use crate::aggregation::{
    aggregation_proof_uncompressed_len, verify_aggregation_proof_with_metrics,
    warm_aggregation_cache_from_proof_bytes,
};
use crate::batch_proof::decode_flat_batch_proof_bytes;
use crate::commitment_tree::CommitmentTreeState;
use crate::error::ProofError;
use crate::types::{
    Block, DaParams, DaRoot, FeeCommitment, ProofVerificationMode, ProvenBatchMode,
    StarkCommitment, StateRoot, TxStatementBinding, VersionCommitment, compute_fee_commitment,
    compute_proof_commitment, compute_version_commitment, da_root, kernel_root_from_shielded_root,
};
use batch_circuit::{BatchPublicInputs, verify_batch_proof_bytes};
use block_circuit::{CommitmentBlockProof, CommitmentBlockProver, verify_block_commitment};
use crypto::hashes::blake3_384;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::time::Instant;
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::{Felt, ciphertext_hash_bytes, felts_to_bytes48};
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

    let proof_starting_kernel_root = felts_to_bytes48(&proof.public_inputs.starting_kernel_root);
    let expected_starting_kernel_root =
        kernel_root_from_shielded_root(&parent_commitment_tree.root());
    if proof_starting_kernel_root != expected_starting_kernel_root {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "starting kernel root mismatch".to_string(),
        ));
    }

    let proof_ending_kernel_root = felts_to_bytes48(&proof.public_inputs.ending_kernel_root);
    let expected_ending_kernel_root = kernel_root_from_shielded_root(&expected_tree.root());
    if proof_ending_kernel_root != expected_ending_kernel_root {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "ending kernel root mismatch".to_string(),
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
        let start_total = Instant::now();
        let tx_count = block.transactions.len();
        let commitment_proof_bytes = block
            .proven_batch
            .as_ref()
            .map(|batch| batch.commitment_proof.proof_bytes.len())
            .unwrap_or(0);
        let aggregation_proof_bytes = block
            .proven_batch
            .as_ref()
            .map(total_batch_proof_payload_bytes)
            .unwrap_or(0);
        let aggregation_proof_uncompressed_bytes = block
            .proven_batch
            .as_ref()
            .map(total_batch_proof_uncompressed_bytes)
            .unwrap_or(0);
        let ciphertext_bytes_total: usize = block
            .transactions
            .iter()
            .flat_map(|tx| tx.ciphertexts.iter())
            .map(|ct| ct.len())
            .sum();

        if block.transactions.is_empty() {
            if block.proven_batch.is_some() || block.transaction_proofs.is_some() {
                return Err(ProofError::CommitmentProofEmptyBlock);
            }
            return apply_commitments(parent_commitment_tree, &block.transactions);
        }

        let verification_mode = block.proof_verification_mode;
        let transaction_proofs = block.transaction_proofs.as_ref();

        let tx_proof_bytes_total: usize = transaction_proofs
            .map(|proofs| proofs.iter().map(|proof| proof.stark_proof.len()).sum())
            .unwrap_or(0);
        if let Some(proofs) = transaction_proofs
            && proofs.len() != block.transactions.len()
        {
            return Err(ProofError::TransactionProofCountMismatch {
                expected: block.transactions.len(),
                observed: proofs.len(),
            });
        }
        if matches!(verification_mode, ProofVerificationMode::InlineRequired)
            && transaction_proofs.is_none()
        {
            return Err(ProofError::MissingTransactionProofs);
        }

        if block.proven_batch.is_none() {
            if matches!(
                verification_mode,
                ProofVerificationMode::SelfContainedAggregation
            ) {
                return Err(ProofError::MissingProvenBatchForSelfContained);
            }

            let proofs = transaction_proofs.ok_or(ProofError::MissingTransactionProofs)?;
            proofs
                .par_iter()
                .zip(&block.transactions)
                .enumerate()
                .try_for_each(|(index, (proof, tx))| {
                    verify_transaction_proof_inputs(index, tx, proof)?;
                    Ok::<_, ProofError>(())
                })?;
            let start_tx = Instant::now();
            proofs
                .par_iter()
                .enumerate()
                .try_for_each(|(index, proof)| {
                    verify_transaction_proof(proof, &self.verifying_key).map_err(|err| {
                        ProofError::TransactionProofVerification {
                            index,
                            message: err.to_string(),
                        }
                    })?;
                    Ok::<_, ProofError>(())
                })?;
            let tx_verify_ms = start_tx.elapsed().as_millis();

            let expected_tree = apply_commitments(parent_commitment_tree, &block.transactions)?;
            let anchors: Vec<[u8; 48]> = proofs
                .iter()
                .map(|proof| proof.public_inputs.merkle_root)
                .collect();
            let result = verify_and_apply_tree_transition(
                parent_commitment_tree,
                parent_commitment_tree.root(),
                expected_tree.root(),
                &block.transactions,
                &anchors,
            )?;

            tracing::info!(
                target: "consensus::metrics",
                tx_count,
                tx_proof_bytes_total,
                commitment_proof_bytes,
                aggregation_proof_bytes,
                aggregation_proof_uncompressed_bytes,
                ciphertext_bytes_total,
                commitment_verify_ms = 0u128,
                aggregation_verify_ms = 0u128,
                aggregation_verify_batch_ms = 0u128,
                aggregation_cache_hit = false,
                aggregation_cache_build_ms = 0u128,
                aggregation_cache_prewarm_hit = false,
                aggregation_cache_prewarm_build_ms = 0u128,
                aggregation_cache_prewarm_total_ms = 0u128,
                tx_verify_ms,
                total_verify_ms = start_total.elapsed().as_millis(),
                aggregation_verified = false,
                "block_proof_verification_metrics"
            );
            return Ok(result);
        }

        let proven_batch = block
            .proven_batch
            .as_ref()
            .ok_or(ProofError::MissingCommitmentProof)?;
        let commitment_proof = &proven_batch.commitment_proof;

        let start_commitment = Instant::now();
        verify_commitment_proof_payload(block, parent_commitment_tree, commitment_proof)?;
        let commitment_verify_ms = start_commitment.elapsed().as_millis();

        let resolved_statement_bindings =
            if let Some(bindings) = block.tx_statement_bindings.clone() {
                if bindings.len() != block.transactions.len() {
                    return Err(ProofError::CommitmentProofInputsMismatch(format!(
                        "transaction statement binding count mismatch (expected {}, got {})",
                        block.transactions.len(),
                        bindings.len()
                    )));
                }
                Some(bindings)
            } else if matches!(verification_mode, ProofVerificationMode::InlineRequired) {
                let proofs = transaction_proofs.ok_or(ProofError::MissingTransactionProofs)?;
                Some(statement_bindings_from_transaction_proofs(proofs)?)
            } else {
                None
            };

        if matches!(
            verification_mode,
            ProofVerificationMode::SelfContainedAggregation
        ) && resolved_statement_bindings.is_none()
        {
            return Err(ProofError::MissingTransactionStatementBindings);
        }

        let derived_statement_commitment = resolved_statement_bindings
            .as_deref()
            .map(commitment_from_statement_bindings)
            .transpose()?;

        let expected_commitment =
            match (block.tx_statements_commitment, derived_statement_commitment) {
                (Some(expected), Some(derived)) => {
                    if expected != derived {
                        return Err(ProofError::CommitmentProofInputsMismatch(
                            "tx_statements_commitment does not match provided statement bindings"
                                .to_string(),
                        ));
                    }
                    expected
                }
                (Some(expected), None) => expected,
                (None, Some(derived)) => derived,
                (None, None) => {
                    return Err(ProofError::MissingTransactionStatementBindings);
                }
            };
        let proof_commitment =
            felts_to_bytes48(&commitment_proof.public_inputs.tx_statements_commitment);
        if expected_commitment != proof_commitment {
            return Err(ProofError::CommitmentProofInputsMismatch(
                "tx_statements_commitment mismatch".to_string(),
            ));
        }

        if matches!(verification_mode, ProofVerificationMode::InlineRequired)
            && let Some(proofs) = transaction_proofs
        {
            proofs
                .par_iter()
                .zip(&block.transactions)
                .enumerate()
                .try_for_each(|(index, (proof, tx))| {
                    verify_transaction_proof_inputs(index, tx, proof)?;
                    Ok::<_, ProofError>(())
                })?;
        }

        let mut tx_verify_ms = 0u128;

        let mut aggregation_cache_hit = None;
        let mut aggregation_cache_build_ms = None;
        let mut aggregation_cache_prewarm_hit = None;
        let mut aggregation_cache_prewarm_build_ms = None;
        let mut aggregation_cache_prewarm_total_ms = None;
        let (aggregation_verified, aggregation_verify_ms, aggregation_verify_batch_ms) =
            match proven_batch.mode {
                ProvenBatchMode::FlatBatches => {
                    let statement_bindings = resolved_statement_bindings
                        .as_deref()
                        .ok_or(ProofError::MissingTransactionStatementBindings)?;
                    let start_flat = Instant::now();
                    verify_flat_batch_payload(
                        &self.verifying_key,
                        &proven_batch.flat_batches,
                        &block.transactions,
                        statement_bindings,
                        &expected_commitment,
                    )?;
                    let verify_ms = start_flat.elapsed().as_millis();
                    (true, verify_ms, verify_ms)
                }
                ProvenBatchMode::MergeRoot => {
                    let merge_root = proven_batch.merge_root.as_ref().ok_or_else(|| {
                        ProofError::ProvenBatchBindingMismatch(
                            "missing merge_root payload for MergeRoot mode".to_string(),
                        )
                    })?;
                    let statement_bindings = resolved_statement_bindings
                        .as_deref()
                        .ok_or(ProofError::MissingTransactionStatementBindings)?;
                    let statement_hashes = statement_bindings
                        .iter()
                        .map(|binding| binding.statement_hash)
                        .collect::<Vec<_>>();
                    let expected_leaf_count =
                        statement_hashes.len().div_ceil(merge_root_leaf_fan_in_from_env()) as u32;
                    if merge_root.metadata.leaf_count != expected_leaf_count {
                        return Err(ProofError::ProvenBatchBindingMismatch(format!(
                            "merge-root leaf_count mismatch (payload {}, expected {})",
                            merge_root.metadata.leaf_count, expected_leaf_count
                        )));
                    }
                    let expected_tree_levels = expected_merge_root_tree_levels(tx_count);
                    if merge_root.metadata.tree_levels != expected_tree_levels {
                        return Err(ProofError::ProvenBatchBindingMismatch(format!(
                            "merge-root tree_levels mismatch (payload {}, expected {})",
                            merge_root.metadata.tree_levels, expected_tree_levels
                        )));
                    }
                    let expected_leaf_manifest =
                        merge_root_leaf_manifest_commitment_from_statement_hashes(
                            &statement_hashes,
                        )?;
                    if merge_root.metadata.leaf_manifest_commitment != expected_leaf_manifest {
                        return Err(ProofError::ProvenBatchBindingMismatch(
                            "merge-root leaf_manifest_commitment mismatch".to_string(),
                        ));
                    }
                    if merge_root.root_proof.is_empty() {
                        return Err(ProofError::MissingAggregationProofForSelfContainedMode);
                    }

                    let prewarm_start = Instant::now();
                    match warm_aggregation_cache_from_proof_bytes(
                        &merge_root.root_proof,
                        tx_count,
                        &expected_commitment,
                    ) {
                        Ok(warmup) => {
                            aggregation_cache_prewarm_hit = Some(warmup.cache_hit);
                            aggregation_cache_prewarm_build_ms = Some(warmup.cache_build_ms);
                        }
                        Err(err) => {
                            tracing::debug!(
                                target: "consensus::metrics",
                                ?err,
                                tx_count,
                                "aggregation cache prewarm failed"
                            );
                        }
                    }
                    aggregation_cache_prewarm_total_ms = Some(prewarm_start.elapsed().as_millis());

                    let verify_metrics = verify_aggregation_proof_with_metrics(
                        &merge_root.root_proof,
                        tx_count,
                        &expected_commitment,
                    )?;
                    aggregation_cache_hit = Some(verify_metrics.cache_hit);
                    aggregation_cache_build_ms = Some(verify_metrics.cache_build_ms);
                    (
                        true,
                        verify_metrics.total_ms,
                        verify_metrics.verify_batch_ms,
                    )
                }
            };

        if !aggregation_verified {
            match verification_mode {
                ProofVerificationMode::InlineRequired => {
                    let transaction_proofs =
                        transaction_proofs.ok_or(ProofError::MissingTransactionProofs)?;
                    let start_tx = Instant::now();
                    transaction_proofs
                        .par_iter()
                        .enumerate()
                        .try_for_each(|(index, proof)| {
                            verify_transaction_proof(proof, &self.verifying_key).map_err(
                                |err| ProofError::TransactionProofVerification {
                                    index,
                                    message: err.to_string(),
                                },
                            )?;
                            Ok::<_, ProofError>(())
                        })?;
                    tx_verify_ms = start_tx.elapsed().as_millis();
                }
                ProofVerificationMode::SelfContainedAggregation => {
                    return Err(ProofError::MissingAggregationProofForSelfContainedMode);
                }
            }
        }

        let proof_starting_root =
            felts_to_bytes48(&commitment_proof.public_inputs.starting_state_root);
        let proof_ending_root = felts_to_bytes48(&commitment_proof.public_inputs.ending_state_root);
        let result = if matches!(verification_mode, ProofVerificationMode::InlineRequired) {
            let proofs = transaction_proofs.ok_or(ProofError::MissingTransactionProofs)?;
            let anchors: Vec<[u8; 48]> = proofs
                .iter()
                .map(|proof| proof.public_inputs.merkle_root)
                .collect();
            verify_and_apply_tree_transition(
                parent_commitment_tree,
                proof_starting_root,
                proof_ending_root,
                &block.transactions,
                &anchors,
            )?
        } else {
            verify_and_apply_tree_transition_without_anchors(
                parent_commitment_tree,
                proof_starting_root,
                proof_ending_root,
                &block.transactions,
            )?
        };

        tracing::info!(
            target: "consensus::metrics",
            tx_count,
            tx_proof_bytes_total,
            commitment_proof_bytes,
            aggregation_proof_bytes,
            aggregation_proof_uncompressed_bytes,
            ciphertext_bytes_total,
            commitment_verify_ms,
            aggregation_verify_ms,
            aggregation_verify_batch_ms,
            aggregation_cache_hit = aggregation_cache_hit.unwrap_or(false),
            aggregation_cache_build_ms = aggregation_cache_build_ms.unwrap_or(0),
            aggregation_cache_prewarm_hit = aggregation_cache_prewarm_hit.unwrap_or(false),
            aggregation_cache_prewarm_build_ms = aggregation_cache_prewarm_build_ms.unwrap_or(0),
            aggregation_cache_prewarm_total_ms = aggregation_cache_prewarm_total_ms.unwrap_or(0),
            tx_verify_ms,
            total_verify_ms = start_total.elapsed().as_millis(),
            aggregation_verified,
            "block_proof_verification_metrics"
        );

        Ok(result)
    }
}

pub trait HeaderProofExt {
    fn proof_commitment(&self) -> StarkCommitment;
    fn fee_commitment(&self) -> FeeCommitment;
    fn transaction_count(&self) -> u32;
    fn version_commitment(&self) -> VersionCommitment;
    fn da_root(&self) -> DaRoot;
    fn da_params(&self) -> DaParams;
    fn kernel_root(&self) -> StateRoot;
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

    fn kernel_root(&self) -> StateRoot {
        self.kernel_root
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

fn statement_bindings_from_transaction_proofs(
    proofs: &[transaction_circuit::TransactionProof],
) -> Result<Vec<TxStatementBinding>, ProofError> {
    let mut bindings = Vec::with_capacity(proofs.len());
    for proof in proofs {
        bindings.push(statement_binding_from_proof(proof));
    }
    Ok(bindings)
}

fn commitment_from_statement_bindings(
    bindings: &[TxStatementBinding],
) -> Result<[u8; 48], ProofError> {
    let hashes = bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect::<Vec<_>>();
    CommitmentBlockProver::commitment_from_statement_hashes(&hashes)
        .map_err(|err| ProofError::CommitmentProofInputsMismatch(err.to_string()))
}

fn merge_root_leaf_fan_in_from_env() -> usize {
    std::env::var("HEGEMON_AGG_LEAF_FANIN")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(8)
        .max(1)
}

fn expected_merge_root_tree_levels(tx_count: usize) -> u16 {
    if tx_count <= merge_root_leaf_fan_in_from_env() {
        1
    } else {
        2
    }
}

fn merge_root_leaf_manifest_commitment_from_statement_hashes(
    statement_hashes: &[[u8; 48]],
) -> Result<[u8; 48], ProofError> {
    let leaf_fan_in = merge_root_leaf_fan_in_from_env();
    let mut manifest_material = Vec::new();
    manifest_material.extend_from_slice(b"agg-leaf-manifest-v1");
    manifest_material.extend_from_slice(&(leaf_fan_in as u16).to_le_bytes());
    manifest_material.extend_from_slice(&(statement_hashes.len() as u32).to_le_bytes());
    for (leaf_index, chunk) in statement_hashes.chunks(leaf_fan_in).enumerate() {
        let leaf_commitment = CommitmentBlockProver::commitment_from_statement_hashes(chunk)
            .map_err(|err| ProofError::AggregationProofInputsMismatch(err.to_string()))?;
        let mut descriptor = Vec::new();
        descriptor.extend_from_slice(b"agg-leaf-v1");
        descriptor.extend_from_slice(&(leaf_index as u32).to_le_bytes());
        descriptor.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        descriptor.extend_from_slice(&leaf_commitment);
        manifest_material.extend_from_slice(&blake3_384(&descriptor));
    }
    Ok(blake3_384(&manifest_material))
}

fn total_batch_proof_payload_bytes(batch: &crate::types::ProvenBatch) -> usize {
    match batch.mode {
        ProvenBatchMode::FlatBatches => {
            batch.flat_batches.iter().map(|item| item.proof.len()).sum()
        }
        ProvenBatchMode::MergeRoot => batch
            .merge_root
            .as_ref()
            .map(|merge| merge.root_proof.len())
            .unwrap_or(0),
    }
}

fn total_batch_proof_uncompressed_bytes(batch: &crate::types::ProvenBatch) -> usize {
    match batch.mode {
        ProvenBatchMode::FlatBatches => {
            batch.flat_batches.iter().map(|item| item.proof.len()).sum()
        }
        ProvenBatchMode::MergeRoot => batch
            .merge_root
            .as_ref()
            .map(|merge| aggregation_proof_uncompressed_len(&merge.root_proof))
            .unwrap_or(0),
    }
}

fn verify_flat_batch_payload(
    _verifying_key: &transaction_circuit::keys::VerifyingKey,
    flat_batches: &[crate::types::BatchProofItem],
    transactions: &[crate::types::Transaction],
    statement_bindings: &[TxStatementBinding],
    expected_commitment: &[u8; 48],
) -> Result<(), ProofError> {
    if flat_batches.is_empty() {
        return Err(ProofError::MissingAggregationProofForSelfContainedMode);
    }
    if transactions.is_empty() {
        return Err(ProofError::AggregationProofEmptyBlock);
    }
    if statement_bindings.len() != transactions.len() {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "statement binding count mismatch (expected {}, got {})",
            transactions.len(),
            statement_bindings.len()
        )));
    }

    let mut ordered: Vec<&crate::types::BatchProofItem> = flat_batches.iter().collect();
    ordered.sort_by_key(|item| item.start_tx_index);

    let mut expected_start: usize = 0;
    let mut all_statement_hashes: Vec<[u8; 48]> = Vec::with_capacity(transactions.len());

    for item in ordered {
        if item.tx_count == 0 {
            return Err(ProofError::FlatBatchCoverage(
                "flat batch item tx_count must be non-zero".to_string(),
            ));
        }
        if item.proof_format != crate::types::BLOCK_PROOF_FORMAT_ID_V5 {
            return Err(ProofError::FlatBatchCoverage(format!(
                "flat batch item uses unsupported proof format {}",
                item.proof_format
            )));
        }

        let start = item.start_tx_index as usize;
        if start != expected_start {
            let reason = if start < expected_start {
                "overlap"
            } else {
                "gap"
            };
            return Err(ProofError::FlatBatchCoverage(format!(
                "flat batch coverage {reason}: expected start {expected_start}, got {start}"
            )));
        }

        let end = start.checked_add(item.tx_count as usize).ok_or_else(|| {
            ProofError::FlatBatchCoverage("flat batch coverage overflow".to_string())
        })?;
        if end > transactions.len() {
            return Err(ProofError::FlatBatchCoverage(format!(
                "flat batch range [{start}, {end}) exceeds tx_count {}",
                transactions.len()
            )));
        }

        let payload = decode_flat_batch_proof_bytes(&item.proof)?;
        let batch_public_inputs = decode_batch_public_inputs(&payload.batch_public_values)?;

        if batch_public_inputs.batch_size as usize != (end - start) {
            return Err(ProofError::FlatBatchCoverage(format!(
                "flat batch public input tx_count mismatch: expected {}, got {}",
                end - start,
                batch_public_inputs.batch_size
            )));
        }

        let binding_subset = &statement_bindings[start..end];
        verify_flat_batch_public_inputs_binding(&batch_public_inputs, binding_subset, start, end)?;

        verify_batch_proof_bytes(&payload.batch_proof, &batch_public_inputs).map_err(|err| {
            ProofError::AggregationProofVerification(format!(
                "flat batch STARK verification failed at tx range [{start}, {end}): {err}"
            ))
        })?;

        let tx_subset = &transactions[start..end];
        let expected_nullifiers = padded_nullifiers_from_transactions(tx_subset);
        let expected_commitments = padded_commitments_from_transactions(tx_subset);
        let active_nullifier_len = (end - start) * MAX_INPUTS;
        let active_commitment_len = (end - start) * MAX_OUTPUTS;

        if batch_public_inputs.nullifiers.len() < active_nullifier_len {
            return Err(ProofError::FlatBatchCoverage(format!(
                "flat batch public nullifier vector too short: expected at least {}, got {}",
                active_nullifier_len,
                batch_public_inputs.nullifiers.len()
            )));
        }
        if batch_public_inputs.commitments.len() < active_commitment_len {
            return Err(ProofError::FlatBatchCoverage(format!(
                "flat batch public commitment vector too short: expected at least {}, got {}",
                active_commitment_len,
                batch_public_inputs.commitments.len()
            )));
        }

        let observed_active_nullifiers: Vec<[u8; 48]> = batch_public_inputs
            .nullifiers
            .iter()
            .take(active_nullifier_len)
            .map(felts_to_bytes48)
            .collect();
        if observed_active_nullifiers != expected_nullifiers {
            return Err(ProofError::ProvenBatchBindingMismatch(format!(
                "flat batch nullifier mismatch in tx range [{start}, {end})"
            )));
        }

        let observed_active_commitments: Vec<[u8; 48]> = batch_public_inputs
            .commitments
            .iter()
            .take(active_commitment_len)
            .map(felts_to_bytes48)
            .collect();
        if observed_active_commitments != expected_commitments {
            return Err(ProofError::ProvenBatchBindingMismatch(format!(
                "flat batch commitment mismatch in tx range [{start}, {end})"
            )));
        }

        if batch_public_inputs
            .nullifiers
            .iter()
            .skip(active_nullifier_len)
            .any(|value| felts_to_bytes48(value) != [0u8; 48])
        {
            return Err(ProofError::ProvenBatchBindingMismatch(format!(
                "flat batch inactive nullifier tail is non-zero in tx range [{start}, {end})"
            )));
        }
        if batch_public_inputs
            .commitments
            .iter()
            .skip(active_commitment_len)
            .any(|value| felts_to_bytes48(value) != [0u8; 48])
        {
            return Err(ProofError::ProvenBatchBindingMismatch(format!(
                "flat batch inactive commitment tail is non-zero in tx range [{start}, {end})"
            )));
        }

        all_statement_hashes.extend(binding_subset.iter().map(|binding| binding.statement_hash));
        expected_start = end;
    }

    if expected_start != transactions.len() {
        return Err(ProofError::FlatBatchCoverage(format!(
            "flat batch coverage incomplete: covered {expected_start}, expected {}",
            transactions.len()
        )));
    }

    let observed_commitment =
        CommitmentBlockProver::commitment_from_statement_hashes(&all_statement_hashes)
            .map_err(|err| ProofError::AggregationProofInputsMismatch(err.to_string()))?;
    if &observed_commitment != expected_commitment {
        return Err(ProofError::ProvenBatchBindingMismatch(
            "flat batch statement commitment mismatch".to_string(),
        ));
    }

    Ok(())
}

fn decode_batch_public_inputs(values: &[u64]) -> Result<BatchPublicInputs, ProofError> {
    let felts: Vec<Felt> = values.iter().map(|value| Felt::from_u64(*value)).collect();
    BatchPublicInputs::try_from_slice(&felts).map_err(|err| {
        ProofError::FlatBatchProofDecodeFailed(format!(
            "flat batch public input decode failed: {err}"
        ))
    })
}

fn padded_nullifiers_from_transactions(
    transactions: &[crate::types::Transaction],
) -> Vec<[u8; 48]> {
    let mut out = Vec::with_capacity(transactions.len().saturating_mul(MAX_INPUTS));
    for tx in transactions {
        out.extend_from_slice(&tx.nullifiers);
        out.extend(std::iter::repeat_n(
            [0u8; 48],
            MAX_INPUTS.saturating_sub(tx.nullifiers.len()),
        ));
    }
    out
}

fn padded_commitments_from_transactions(
    transactions: &[crate::types::Transaction],
) -> Vec<[u8; 48]> {
    let mut out = Vec::with_capacity(transactions.len().saturating_mul(MAX_OUTPUTS));
    for tx in transactions {
        out.extend_from_slice(&tx.commitments);
        out.extend(std::iter::repeat_n(
            [0u8; 48],
            MAX_OUTPUTS.saturating_sub(tx.commitments.len()),
        ));
    }
    out
}

fn verify_flat_batch_public_inputs_binding(
    batch_public_inputs: &BatchPublicInputs,
    bindings: &[TxStatementBinding],
    start: usize,
    end: usize,
) -> Result<(), ProofError> {
    let first = bindings.first().ok_or_else(|| {
        ProofError::FlatBatchCoverage("empty statement binding subset".to_string())
    })?;
    let expected_anchor = first.anchor;
    if bindings
        .iter()
        .any(|binding| binding.anchor != expected_anchor)
    {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "flat batch statement bindings contain mixed anchors in tx range [{start}, {end})"
        )));
    }

    let observed_anchor = felts_to_bytes48(&batch_public_inputs.anchor);
    if observed_anchor != expected_anchor {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "flat batch anchor mismatch in tx range [{start}, {end})"
        )));
    }

    let expected_fee = bindings.iter().fold(0u128, |acc, binding| {
        acc.saturating_add(u128::from(binding.fee))
    });
    let observed_fee = u128::from(batch_public_inputs.total_fee.as_canonical_u64());
    if observed_fee != expected_fee {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "flat batch total fee mismatch in tx range [{start}, {end})"
        )));
    }

    let expected_circuit_version = first.circuit_version;
    if bindings
        .iter()
        .any(|binding| binding.circuit_version != expected_circuit_version)
    {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "flat batch statement bindings contain mixed circuit versions in tx range [{start}, {end})"
        )));
    }
    if batch_public_inputs.circuit_version != expected_circuit_version {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "flat batch circuit version mismatch in tx range [{start}, {end})"
        )));
    }

    Ok(())
}

fn statement_hash_from_proof(proof: &transaction_circuit::TransactionProof) -> [u8; 48] {
    let public = &proof.public_inputs;
    let mut message = Vec::new();
    message.extend_from_slice(b"tx-statement-v1");
    message.extend_from_slice(&public.merkle_root);
    for nf in &public.nullifiers {
        message.extend_from_slice(nf);
    }
    for cm in &public.commitments {
        message.extend_from_slice(cm);
    }
    for ct in &public.ciphertext_hashes {
        message.extend_from_slice(ct);
    }
    message.extend_from_slice(&public.native_fee.to_le_bytes());
    message.extend_from_slice(&public.value_balance.to_le_bytes());
    message.extend_from_slice(&public.balance_tag);
    message.extend_from_slice(&public.circuit_version.to_le_bytes());
    message.extend_from_slice(&public.crypto_suite.to_le_bytes());
    message.push(public.stablecoin.enabled as u8);
    message.extend_from_slice(&public.stablecoin.asset_id.to_le_bytes());
    message.extend_from_slice(&public.stablecoin.policy_hash);
    message.extend_from_slice(&public.stablecoin.oracle_commitment);
    message.extend_from_slice(&public.stablecoin.attestation_commitment);
    message.extend_from_slice(&public.stablecoin.issuance_delta.to_le_bytes());
    message.extend_from_slice(&public.stablecoin.policy_version.to_le_bytes());
    blake3_384(&message)
}

fn statement_binding_from_proof(
    proof: &transaction_circuit::TransactionProof,
) -> TxStatementBinding {
    TxStatementBinding {
        statement_hash: statement_hash_from_proof(proof),
        anchor: proof.public_inputs.merkle_root,
        fee: proof.public_inputs.native_fee,
        circuit_version: u32::from(proof.public_inputs.circuit_version),
    }
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

    if !tx.ciphertexts.is_empty() {
        let mut derived_hashes: Vec<[u8; 48]> = tx
            .ciphertexts
            .iter()
            .map(|ct| ciphertext_hash_bytes(ct))
            .collect();
        derived_hashes.resize(MAX_OUTPUTS, [0u8; 48]);
        if derived_hashes != proof.public_inputs.ciphertext_hashes {
            return Err(ProofError::TransactionProofInputsMismatch {
                index,
                message: "ciphertext hash mismatch".to_string(),
            });
        }
    }

    let mut expected_ciphertext_hashes = tx.ciphertext_hashes.clone();
    expected_ciphertext_hashes.resize(MAX_OUTPUTS, [0u8; 48]);
    if expected_ciphertext_hashes != proof.public_inputs.ciphertext_hashes {
        return Err(ProofError::TransactionProofInputsMismatch {
            index,
            message: "ciphertext hash mismatch".to_string(),
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

fn verify_and_apply_tree_transition_without_anchors(
    parent_commitment_tree: &CommitmentTreeState,
    proof_starting_root: [u8; 48],
    proof_ending_root: [u8; 48],
    transactions: &[crate::types::Transaction],
) -> Result<CommitmentTreeState, ProofError> {
    if proof_starting_root != parent_commitment_tree.root() {
        return Err(ProofError::StartingRootMismatch {
            expected: parent_commitment_tree.root(),
            observed: proof_starting_root,
        });
    }
    let tree = apply_commitments(parent_commitment_tree, transactions)?;
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
    use transaction_circuit::hashing_pq::bytes48_to_felts;

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

    fn binding(anchor: [u8; 48], fee: u64, circuit_version: u32) -> TxStatementBinding {
        TxStatementBinding {
            statement_hash: [5u8; 48],
            anchor,
            fee,
            circuit_version,
        }
    }

    fn batch_inputs(anchor: [u8; 48], fee: u64, circuit_version: u32) -> BatchPublicInputs {
        let mut inputs = BatchPublicInputs::default();
        inputs.batch_size = 1;
        inputs.anchor = bytes48_to_felts(&anchor).expect("canonical anchor");
        inputs.total_fee = Felt::from_u64(fee);
        inputs.circuit_version = circuit_version;
        inputs
    }

    #[test]
    fn flat_batch_binding_rejects_anchor_mismatch() {
        let inputs = batch_inputs([1u8; 48], 10, 1);
        let bindings = vec![binding([2u8; 48], 10, 1)];
        let err = verify_flat_batch_public_inputs_binding(&inputs, &bindings, 0, 1)
            .expect_err("anchor mismatch should fail");
        assert!(matches!(err, ProofError::ProvenBatchBindingMismatch(_)));
    }

    #[test]
    fn flat_batch_binding_rejects_fee_mismatch() {
        let inputs = batch_inputs([1u8; 48], 11, 1);
        let bindings = vec![binding([1u8; 48], 10, 1)];
        let err = verify_flat_batch_public_inputs_binding(&inputs, &bindings, 0, 1)
            .expect_err("fee mismatch should fail");
        assert!(matches!(err, ProofError::ProvenBatchBindingMismatch(_)));
    }

    #[test]
    fn flat_batch_binding_rejects_circuit_version_mismatch() {
        let inputs = batch_inputs([1u8; 48], 10, 2);
        let bindings = vec![binding([1u8; 48], 10, 1)];
        let err = verify_flat_batch_public_inputs_binding(&inputs, &bindings, 0, 1)
            .expect_err("version mismatch should fail");
        assert!(matches!(err, ProofError::ProvenBatchBindingMismatch(_)));
    }

    #[test]
    fn flat_batch_binding_rejects_mixed_anchor_context() {
        let inputs = batch_inputs([1u8; 48], 20, 1);
        let bindings = vec![binding([1u8; 48], 10, 1), binding([2u8; 48], 10, 1)];
        let err = verify_flat_batch_public_inputs_binding(&inputs, &bindings, 0, 2)
            .expect_err("mixed anchor context should fail");
        assert!(matches!(err, ProofError::ProvenBatchBindingMismatch(_)));
    }
}
