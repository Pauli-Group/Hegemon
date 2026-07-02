use crate::backend_interface::{
    CanonicalTxValidityReceipt, NativeTxLeafRecord, TransactionProof,
    build_native_tx_leaf_receipt_root_artifact_bytes, build_receipt_root_artifact_bytes,
    build_verified_tx_proof_receipt_root_artifact_bytes, decode_native_tx_leaf_artifact_bytes,
    experimental_native_receipt_root_params_fingerprint as backend_native_receipt_root_params_fingerprint,
    experimental_native_receipt_root_verifier_profile_digest as backend_native_receipt_root_profile,
    experimental_native_tx_leaf_verifier_profile_digest as backend_native_tx_leaf_profile,
    experimental_receipt_root_verifier_profile_digest as backend_receipt_root_profile,
    experimental_tx_leaf_verifier_profile_digest as backend_tx_leaf_profile, native_backend_params,
    verify_native_tx_leaf_receipt_root_artifact_bytes,
    verify_native_tx_leaf_receipt_root_artifact_from_records_with_params,
    verify_receipt_root_artifact_bytes, verify_verified_tx_proof_receipt_root_artifact_bytes,
};
use crate::commitment_tree::CommitmentTreeState;
use crate::error::ProofError;
use crate::types::{
    Block, DaParams, DaRoot, FeeCommitment, ProofArtifactKind, ReceiptRootMetadata,
    StarkCommitment, StateRoot, TxStatementBinding, TxValidityArtifact, TxValidityClaim,
    TxValidityReceipt, VerifierProfileDigest, VersionCommitment, compute_fee_commitment,
    compute_proof_commitment,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentalReceiptRootArtifact {
    pub artifact_bytes: Vec<u8>,
    pub metadata: ReceiptRootMetadata,
}

pub fn experimental_receipt_root_verifier_profile() -> VerifierProfileDigest {
    backend_receipt_root_profile()
}

pub fn experimental_tx_leaf_verifier_profile() -> VerifierProfileDigest {
    backend_tx_leaf_profile()
}

pub fn experimental_native_tx_leaf_verifier_profile() -> VerifierProfileDigest {
    backend_native_tx_leaf_profile()
}

pub fn experimental_native_receipt_root_verifier_profile() -> VerifierProfileDigest {
    backend_native_receipt_root_profile()
}

pub fn experimental_native_receipt_root_params_fingerprint() -> [u8; 48] {
    backend_native_receipt_root_params_fingerprint()
}

pub fn build_experimental_receipt_root_artifact(
    receipts: &[TxValidityReceipt],
) -> Result<ExperimentalReceiptRootArtifact, ProofError> {
    let canonical = canonical_receipts_from_tx_receipts(receipts);
    let built = build_receipt_root_artifact_bytes(&canonical)
        .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    Ok(ExperimentalReceiptRootArtifact {
        artifact_bytes: built.artifact_bytes,
        metadata: ReceiptRootMetadata {
            params_fingerprint: built.metadata.params_fingerprint,
            relation_id: built.metadata.relation_id,
            shape_digest: built.metadata.shape_digest,
            leaf_count: built.metadata.leaf_count,
            fold_count: built.metadata.fold_count,
        },
    })
}

pub fn build_experimental_receipt_root_artifact_from_proofs(
    proofs: &[TransactionProof],
) -> Result<ExperimentalReceiptRootArtifact, ProofError> {
    let built = build_verified_tx_proof_receipt_root_artifact_bytes(proofs)
        .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    Ok(ExperimentalReceiptRootArtifact {
        artifact_bytes: built.artifact_bytes,
        metadata: ReceiptRootMetadata {
            params_fingerprint: built.metadata.params_fingerprint,
            relation_id: built.metadata.relation_id,
            shape_digest: built.metadata.shape_digest,
            leaf_count: built.metadata.leaf_count,
            fold_count: built.metadata.fold_count,
        },
    })
}

pub fn build_experimental_native_receipt_root_artifact(
    tx_artifacts: &[TxValidityArtifact],
) -> Result<ExperimentalReceiptRootArtifact, ProofError> {
    let native_artifacts = tx_artifacts
        .iter()
        .map(|artifact| {
            let envelope = artifact
                .proof
                .as_ref()
                .ok_or(ProofError::MissingTransactionProofs)?;
            if envelope.kind != ProofArtifactKind::TxLeaf
                || envelope.verifier_profile != experimental_native_tx_leaf_verifier_profile()
            {
                return Err(ProofError::UnsupportedProofArtifact(
                    "native receipt-root requires native tx-leaf artifacts".to_string(),
                ));
            }
            decode_native_tx_leaf_artifact_bytes(&envelope.artifact_bytes).map_err(|err| {
                ProofError::TransactionProofVerification {
                    index: 0,
                    message: format!("failed to decode native tx-leaf artifact: {err}"),
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let built = build_native_tx_leaf_receipt_root_artifact_bytes(&native_artifacts)
        .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    Ok(ExperimentalReceiptRootArtifact {
        artifact_bytes: built.artifact_bytes,
        metadata: ReceiptRootMetadata {
            params_fingerprint: built.metadata.params_fingerprint,
            relation_id: built.metadata.relation_id,
            shape_digest: built.metadata.shape_digest,
            leaf_count: built.metadata.leaf_count,
            fold_count: built.metadata.fold_count,
        },
    })
}

pub fn verify_experimental_receipt_root_artifact(
    receipts: &[TxValidityReceipt],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata, ProofError> {
    let canonical = canonical_receipts_from_tx_receipts(receipts);
    let metadata = verify_receipt_root_artifact_bytes(&canonical, artifact_bytes)
        .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    Ok(ReceiptRootMetadata {
        params_fingerprint: metadata.params_fingerprint,
        relation_id: metadata.relation_id,
        shape_digest: metadata.shape_digest,
        leaf_count: metadata.leaf_count,
        fold_count: metadata.fold_count,
    })
}

pub fn verify_experimental_receipt_root_artifact_from_proofs(
    proofs: &[TransactionProof],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata, ProofError> {
    let metadata = verify_verified_tx_proof_receipt_root_artifact_bytes(proofs, artifact_bytes)
        .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    Ok(ReceiptRootMetadata {
        params_fingerprint: metadata.params_fingerprint,
        relation_id: metadata.relation_id,
        shape_digest: metadata.shape_digest,
        leaf_count: metadata.leaf_count,
        fold_count: metadata.fold_count,
    })
}

pub fn verify_experimental_native_receipt_root_artifact(
    tx_artifacts: &[TxValidityArtifact],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata, ProofError> {
    let native_artifacts = tx_artifacts
        .iter()
        .map(|artifact| {
            let envelope = artifact
                .proof
                .as_ref()
                .ok_or(ProofError::MissingTransactionProofs)?;
            if envelope.kind != ProofArtifactKind::TxLeaf
                || envelope.verifier_profile != experimental_native_tx_leaf_verifier_profile()
            {
                return Err(ProofError::UnsupportedProofArtifact(
                    "native receipt-root requires native tx-leaf artifacts".to_string(),
                ));
            }
            decode_native_tx_leaf_artifact_bytes(&envelope.artifact_bytes).map_err(|err| {
                ProofError::TransactionProofVerification {
                    index: 0,
                    message: format!("failed to decode native tx-leaf artifact: {err}"),
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let metadata =
        verify_native_tx_leaf_receipt_root_artifact_bytes(&native_artifacts, artifact_bytes)
            .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    Ok(ReceiptRootMetadata {
        params_fingerprint: metadata.params_fingerprint,
        relation_id: metadata.relation_id,
        shape_digest: metadata.shape_digest,
        leaf_count: metadata.leaf_count,
        fold_count: metadata.fold_count,
    })
}

pub fn verify_experimental_native_receipt_root_artifact_from_records(
    records: &[NativeTxLeafRecord],
    artifact_bytes: &[u8],
) -> Result<ReceiptRootMetadata, ProofError> {
    let metadata = verify_native_tx_leaf_receipt_root_artifact_from_records_with_params(
        &native_backend_params(),
        records,
        artifact_bytes,
    )
    .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    Ok(ReceiptRootMetadata {
        params_fingerprint: metadata.params_fingerprint,
        relation_id: metadata.relation_id,
        shape_digest: metadata.shape_digest,
        leaf_count: metadata.leaf_count,
        fold_count: metadata.fold_count,
    })
}

pub fn tx_statement_bindings_from_claims(
    claims: &[TxValidityClaim],
) -> Result<Vec<TxStatementBinding>, ProofError> {
    claims
        .iter()
        .map(validate_tx_validity_claim)
        .collect::<Result<Vec<_>, _>>()
}

pub fn tx_validity_receipts_from_claims(claims: &[TxValidityClaim]) -> Vec<TxValidityReceipt> {
    claims.iter().map(|claim| claim.receipt.clone()).collect()
}

fn validate_tx_validity_claim(claim: &TxValidityClaim) -> Result<TxStatementBinding, ProofError> {
    if claim.receipt.statement_hash != claim.binding.statement_hash {
        return Err(ProofError::AggregationProofInputsMismatch(
            "tx validity claim statement hash mismatch".to_string(),
        ));
    }
    Ok(claim.binding.clone())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlockBackendInputs {
    pub tx_validity_artifacts: Option<Vec<TxValidityArtifact>>,
}

impl BlockBackendInputs {
    pub fn from_tx_validity_artifacts(tx_validity_artifacts: Vec<TxValidityArtifact>) -> Self {
        Self {
            tx_validity_artifacts: Some(tx_validity_artifacts),
        }
    }

    pub fn tx_validity_artifacts(&self) -> Option<&[TxValidityArtifact]> {
        self.tx_validity_artifacts.as_deref()
    }
}

pub trait ProofVerifier: Send + Sync {
    fn verify_block_with_backend<BH>(
        &self,
        block: &Block<BH>,
        backend_inputs: Option<&BlockBackendInputs>,
        parent_commitment_tree: &CommitmentTreeState,
    ) -> Result<CommitmentTreeState, ProofError>
    where
        BH: HeaderProofExt;

    fn verify_block<BH>(
        &self,
        block: &Block<BH>,
        parent_commitment_tree: &CommitmentTreeState,
    ) -> Result<CommitmentTreeState, ProofError>
    where
        BH: HeaderProofExt,
    {
        self.verify_block_with_backend(block, None, parent_commitment_tree)
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
    fn message_root(&self) -> StateRoot {
        [0u8; 48]
    }
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
    Ok(())
}

fn canonical_receipts_from_tx_receipts(
    receipts: &[TxValidityReceipt],
) -> Vec<CanonicalTxValidityReceipt> {
    receipts
        .iter()
        .map(canonical_receipt_from_tx_receipt)
        .collect()
}

pub(crate) fn canonical_receipt_from_tx_receipt(
    receipt: &TxValidityReceipt,
) -> CanonicalTxValidityReceipt {
    CanonicalTxValidityReceipt {
        statement_hash: receipt.statement_hash,
        proof_digest: receipt.proof_digest,
        public_inputs_digest: receipt.public_inputs_digest,
        verifier_profile: receipt.verifier_profile,
    }
}
