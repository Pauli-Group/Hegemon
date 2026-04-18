use consensus::proof::HeaderProofExt;

pub(crate) fn pallet_receipt_from_consensus(
    receipt: consensus::types::TxValidityReceipt,
) -> pallet_shielded_pool::types::TxValidityReceipt {
    pallet_shielded_pool::types::TxValidityReceipt {
        statement_hash: receipt.statement_hash,
        proof_digest: receipt.proof_digest,
        public_inputs_digest: receipt.public_inputs_digest,
        verifier_profile: receipt.verifier_profile,
    }
}

pub(crate) fn consensus_receipt_from_pallet(
    receipt: pallet_shielded_pool::types::TxValidityReceipt,
) -> consensus::types::TxValidityReceipt {
    consensus::types::TxValidityReceipt::new(
        receipt.statement_hash,
        receipt.proof_digest,
        receipt.public_inputs_digest,
        receipt.verifier_profile,
    )
}

pub(crate) fn consensus_receipt_root_payload_from_pallet(
    receipt_root: &pallet_shielded_pool::types::ReceiptRootProofPayload,
) -> consensus::types::ReceiptRootProofPayload {
    consensus::types::ReceiptRootProofPayload {
        root_proof: receipt_root.root_proof.data.clone(),
        metadata: consensus::types::ReceiptRootMetadata {
            params_fingerprint: consensus::experimental_native_receipt_root_params_fingerprint(),
            relation_id: receipt_root.metadata.relation_id,
            shape_digest: receipt_root.metadata.shape_digest,
            leaf_count: receipt_root.metadata.leaf_count,
            fold_count: receipt_root.metadata.fold_count,
        },
        receipts: receipt_root
            .receipts
            .iter()
            .cloned()
            .map(consensus_receipt_from_pallet)
            .collect(),
    }
}

pub(crate) fn claims_and_bindings_from_tx_artifacts(
    transactions: &[consensus::types::Transaction],
    tx_artifacts: &[consensus::TxValidityArtifact],
) -> Result<
    (
        Vec<consensus::TxValidityClaim>,
        Vec<consensus::types::TxStatementBinding>,
    ),
    String,
> {
    let claims = consensus::tx_validity_claims_from_tx_artifacts(transactions, tx_artifacts)
        .map_err(|err| format!("tx validity claims from tx artifacts failed: {err}"))?;
    let bindings = consensus::tx_statement_bindings_from_claims(&claims)
        .map_err(|err| format!("tx statement bindings from tx claims failed: {err}"))?;
    Ok((claims, bindings))
}

pub(crate) fn block_backend_inputs_from_tx_artifacts(
    tx_validity_artifacts: Option<Vec<consensus::TxValidityArtifact>>,
) -> Option<consensus::BlockBackendInputs> {
    tx_validity_artifacts.map(consensus::BlockBackendInputs::from_tx_validity_artifacts)
}

pub(crate) fn verify_block_with_optional_tx_artifacts<V, BH>(
    verifier: &V,
    block: &consensus::types::Block<BH>,
    tx_validity_artifacts: Option<Vec<consensus::TxValidityArtifact>>,
    parent_commitment_tree: &consensus::CommitmentTreeState,
) -> Result<consensus::CommitmentTreeState, consensus::ProofError>
where
    V: consensus::ProofVerifier,
    BH: HeaderProofExt,
{
    let backend_inputs = block_backend_inputs_from_tx_artifacts(tx_validity_artifacts);
    verifier.verify_block_with_backend(block, backend_inputs.as_ref(), parent_commitment_tree)
}
