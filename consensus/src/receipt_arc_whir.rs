use ::receipt_arc_whir::{
    RECEIPT_ARC_WHIR_ARTIFACT_KIND_BYTES, ReceiptArcWhirParams,
    ReceiptResidualVerifyReport as ResidualVerifyReport, ReceiptRow,
    max_receipt_arc_whir_artifact_bytes, prove_receipt_arc_whir, receipt_rows_commitment,
    verify_receipt_arc_whir,
};
use block_circuit::CommitmentBlockProver;
use crypto::hashes::{blake3_256, blake3_384};

use crate::{
    error::ProofError,
    proof::BlockArtifactVerifyReport,
    types::{
        ProofArtifactKind, ProofEnvelope, ReceiptRootMetadata, TxValidityReceipt,
        VerifierProfileDigest,
    },
};

pub const DEFAULT_RECEIPT_ARC_WHIR_PARAMS: ReceiptArcWhirParams = ReceiptArcWhirParams {
    log_blowup: 2,
    query_count: 8,
    folding_rounds: 4,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptArcWhirVerifyDetails {
    pub block_report: BlockArtifactVerifyReport,
    pub residual_report: ReceiptArcWhirResidualReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptArcWhirResidualReport {
    pub row_count: usize,
    pub artifact_bytes: usize,
    pub replayed_leaf_verifications: usize,
    pub used_old_aggregation_backend: bool,
}

pub fn experimental_receipt_arc_whir_artifact_kind() -> ProofArtifactKind {
    ProofArtifactKind::Custom(RECEIPT_ARC_WHIR_ARTIFACT_KIND_BYTES)
}

pub fn experimental_receipt_arc_whir_verifier_profile() -> VerifierProfileDigest {
    blake3_384(b"hegemon:receipt_arc_whir:v1")
}

pub fn receipt_arc_whir_metadata(receipt_count: usize) -> ReceiptRootMetadata {
    let params = DEFAULT_RECEIPT_ARC_WHIR_PARAMS;
    let mut shape_material = Vec::with_capacity(40);
    shape_material.extend_from_slice(b"hegemon:receipt_arc_whir:shape:v1");
    shape_material.push(params.log_blowup);
    shape_material.push(params.query_count);
    shape_material.push(params.folding_rounds);
    ReceiptRootMetadata {
        relation_id: blake3_256(b"hegemon:receipt_arc_whir:relation:v1"),
        shape_digest: blake3_256(&shape_material),
        leaf_count: receipt_count as u32,
        fold_count: effective_folding_rounds(receipt_count, params) as u32,
    }
}

pub fn receipt_row_from_tx_receipt(receipt: &TxValidityReceipt) -> ReceiptRow {
    ReceiptRow {
        statement_hash: receipt.statement_hash,
        proof_digest: receipt.proof_digest,
        public_inputs_digest: receipt.public_inputs_digest,
        verifier_profile: receipt.verifier_profile,
    }
}

pub fn receipt_rows_from_receipts(receipts: &[TxValidityReceipt]) -> Vec<ReceiptRow> {
    receipts.iter().map(receipt_row_from_tx_receipt).collect()
}

pub fn receipt_arc_whir_receipt_commitment(receipts: &[TxValidityReceipt]) -> [u8; 48] {
    let rows = receipt_rows_from_receipts(receipts);
    receipt_rows_commitment(&rows)
}

pub fn receipt_arc_whir_max_artifact_bytes(row_count: usize) -> usize {
    max_receipt_arc_whir_artifact_bytes(row_count)
}

pub fn build_receipt_arc_whir_artifact_from_receipts(
    receipts: &[TxValidityReceipt],
) -> Result<ProofEnvelope, ProofError> {
    let rows = receipt_rows_from_receipts(receipts);
    let artifact_bytes = prove_receipt_arc_whir(&rows, &DEFAULT_RECEIPT_ARC_WHIR_PARAMS)
        .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    Ok(ProofEnvelope {
        kind: experimental_receipt_arc_whir_artifact_kind(),
        verifier_profile: experimental_receipt_arc_whir_verifier_profile(),
        artifact_bytes,
    })
}

pub fn verify_receipt_arc_whir_artifact_from_receipts(
    receipts: &[TxValidityReceipt],
    expected_commitment: &[u8; 48],
    envelope: &ProofEnvelope,
) -> Result<ResidualVerifyReport, ProofError> {
    if envelope.kind != experimental_receipt_arc_whir_artifact_kind() {
        return Err(ProofError::UnsupportedProofArtifact(format!(
            "expected {} block artifact, got {}",
            experimental_receipt_arc_whir_artifact_kind().label(),
            envelope.kind.label()
        )));
    }
    if envelope.verifier_profile != experimental_receipt_arc_whir_verifier_profile() {
        return Err(ProofError::AggregationProofInputsMismatch(
            "receipt_arc_whir verifier profile mismatch".to_string(),
        ));
    }
    if envelope.artifact_bytes.len() > receipt_arc_whir_max_artifact_bytes(receipts.len()) {
        return Err(ProofError::AggregationProofInputsMismatch(format!(
            "receipt_arc_whir artifact size {} exceeds {} for tx_count {}",
            envelope.artifact_bytes.len(),
            receipt_arc_whir_max_artifact_bytes(receipts.len()),
            receipts.len()
        )));
    }

    let derived_statement_commitment = receipt_arc_whir_statement_commitment(receipts)?;
    if derived_statement_commitment != *expected_commitment {
        return Err(ProofError::AggregationProofInputsMismatch(
            "receipt_arc_whir statement commitment mismatch".to_string(),
        ));
    }

    let rows = receipt_rows_from_receipts(receipts);
    verify_receipt_arc_whir(
        &rows,
        &envelope.artifact_bytes,
        &DEFAULT_RECEIPT_ARC_WHIR_PARAMS,
    )
    .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))
}

fn receipt_arc_whir_statement_commitment(
    receipts: &[TxValidityReceipt],
) -> Result<[u8; 48], ProofError> {
    let statement_hashes = receipts
        .iter()
        .map(|receipt| receipt.statement_hash)
        .collect::<Vec<_>>();
    CommitmentBlockProver::commitment_from_statement_hashes(&statement_hashes)
        .map_err(|err| ProofError::AggregationProofInputsMismatch(err.to_string()))
}

fn effective_folding_rounds(row_count: usize, params: ReceiptArcWhirParams) -> usize {
    let base_len = row_count.max(1).next_power_of_two();
    let codeword_len = base_len
        .checked_shl(u32::from(params.log_blowup))
        .unwrap_or(usize::MAX);
    params
        .folding_rounds
        .min(codeword_len.trailing_zeros() as u8) as usize
}
