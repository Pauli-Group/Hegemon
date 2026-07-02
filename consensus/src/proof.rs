use crate::backend_interface::{
    BlockLeafRecordV1, BlockSemanticInputsV1, CommitmentBlockProof, CommitmentBlockProver,
    NativeTxLeafRecord, RECURSIVE_BLOCK_ARTIFACT_VERSION_V1, RECURSIVE_BLOCK_ARTIFACT_VERSION_V2,
    SerializedStarkInputs, TransactionProof, TxLeafPublicTx, build_tx_leaf_artifact_bytes,
    decode_native_tx_leaf_artifact_bytes, decode_transaction_proof_bytes_exact,
    deserialize_recursive_block_artifact_v1, deserialize_recursive_block_artifact_v2,
    max_native_receipt_root_artifact_bytes, max_native_tx_leaf_artifact_bytes,
    native_tx_leaf_record_from_artifact, public_replay_v1, public_replay_v2,
    recursive_block_artifact_verifier_profile_digest_v1 as backend_recursive_block_profile_v1,
    recursive_block_artifact_verifier_profile_digest_v2 as backend_recursive_block_profile_v2,
    transaction_proof_digest, transaction_public_inputs_digest,
    transaction_public_inputs_digest_from_serialized, transaction_statement_hash,
    transaction_statement_hash_checked, transaction_statement_hash_from_parts,
    transaction_verifier_profile_digest, transaction_verifier_profile_digest_for_version,
    verify_block_commitment, verify_block_recursive_v1, verify_block_recursive_v2,
    verify_native_tx_leaf_artifact_bytes, verify_transaction_proof, verify_tx_leaf_artifact_bytes,
};
use crate::commitment_tree::CommitmentTreeState;
use crate::error::ProofError;
use crate::proof_interface::{
    BlockBackendInputs, HeaderProofExt, ProofVerifier, canonical_receipt_from_tx_receipt,
    experimental_native_receipt_root_verifier_profile,
    experimental_native_tx_leaf_verifier_profile, experimental_tx_leaf_verifier_profile,
    tx_statement_bindings_from_claims, tx_validity_receipts_from_claims, verify_commitments,
    verify_experimental_native_receipt_root_artifact,
    verify_experimental_native_receipt_root_artifact_from_records,
};
use crate::types::{
    Block, ProofArtifactKind, ProofEnvelope, ProofVerificationMode, ProvenBatchMode,
    TxStatementBinding, TxValidityArtifact, TxValidityClaim, TxValidityReceipt,
    VerifierProfileDigest, da_root, kernel_root_from_shielded_root,
};
use crypto::hashes::blake3_384;
use parking_lot::Mutex;
use rayon::prelude::*;
use std::any::Any;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::{ciphertext_hash_bytes, felts_to_bytes48};
use transaction_circuit::keys::generate_keys;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentNullifierLists {
    pub nullifiers: Vec<[u8; 48]>,
    pub sorted_nullifiers: Vec<[u8; 48]>,
}

const DEFAULT_NATIVE_TX_LEAF_VERIFY_CACHE_CAPACITY: usize = 4096;
const RECURSIVE_BLOCK_V1_ARTIFACT_MAX_BYTES: usize =
    block_recursion::RECURSIVE_BLOCK_HEADER_BYTES_V1
        + block_recursion::RECURSIVE_BLOCK_PROOF_BYTES_V1
        + block_recursion::RECURSIVE_BLOCK_PUBLIC_BYTES_V1;
const RECURSIVE_BLOCK_V2_ARTIFACT_MAX_BYTES: usize = 523_736;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockProofPolicyInput {
    tx_count: usize,
    verification_mode: ProofVerificationMode,
    has_proven_batch: bool,
    proven_batch_mode: ProvenBatchMode,
    commitment_proof_bytes: usize,
    has_block_artifact: bool,
    has_receipt_root: bool,
    has_tx_validity_artifacts: bool,
    tx_validity_artifact_count: usize,
    has_tx_validity_claims: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockProofPolicyRejection {
    EmptyBlockCarriesProof,
    MissingTransactionProofs,
    TransactionProofCountMismatch,
    UnsupportedInlineRequired,
    MissingProvenBatch,
    MissingTransactionValidityClaims,
    LegacyInlineBatch,
    RecursiveBlockCommitmentProofBytes,
    RecursiveBlockReceiptRootPayload,
    MissingRecursiveBlockArtifact,
    MissingReceiptRootPayload,
}

impl BlockProofPolicyRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::EmptyBlockCarriesProof => "empty_block_carries_proof",
            Self::MissingTransactionProofs => "missing_transaction_proofs",
            Self::TransactionProofCountMismatch => "transaction_proof_count_mismatch",
            Self::UnsupportedInlineRequired => "unsupported_inline_required",
            Self::MissingProvenBatch => "missing_proven_batch",
            Self::MissingTransactionValidityClaims => "missing_transaction_validity_claims",
            Self::LegacyInlineBatch => "legacy_inline_batch",
            Self::RecursiveBlockCommitmentProofBytes => "recursive_block_commitment_proof_bytes",
            Self::RecursiveBlockReceiptRootPayload => "recursive_block_receipt_root_payload",
            Self::MissingRecursiveBlockArtifact => "missing_recursive_block_artifact",
            Self::MissingReceiptRootPayload => "missing_receipt_root_payload",
        }
    }
}

fn evaluate_block_proof_policy(
    input: BlockProofPolicyInput,
) -> Result<(), BlockProofPolicyRejection> {
    if input.tx_count == 0 {
        if input.has_proven_batch
            || input.has_block_artifact
            || input.has_tx_validity_artifacts
            || input.has_tx_validity_claims
        {
            return Err(BlockProofPolicyRejection::EmptyBlockCarriesProof);
        }
        return Ok(());
    }
    if !input.has_tx_validity_artifacts {
        return Err(BlockProofPolicyRejection::MissingTransactionProofs);
    }
    if input.tx_validity_artifact_count != input.tx_count {
        return Err(BlockProofPolicyRejection::TransactionProofCountMismatch);
    }
    if input.verification_mode == ProofVerificationMode::InlineRequired {
        return Err(BlockProofPolicyRejection::UnsupportedInlineRequired);
    }
    if !input.has_proven_batch {
        return Err(BlockProofPolicyRejection::MissingProvenBatch);
    }
    if !input.has_tx_validity_claims {
        return Err(BlockProofPolicyRejection::MissingTransactionValidityClaims);
    }
    match input.proven_batch_mode {
        ProvenBatchMode::InlineTx => Err(BlockProofPolicyRejection::LegacyInlineBatch),
        ProvenBatchMode::ReceiptRoot => {
            if input.has_receipt_root {
                Ok(())
            } else {
                Err(BlockProofPolicyRejection::MissingReceiptRootPayload)
            }
        }
        ProvenBatchMode::RecursiveBlock => {
            if input.commitment_proof_bytes != 0 {
                Err(BlockProofPolicyRejection::RecursiveBlockCommitmentProofBytes)
            } else if input.has_receipt_root {
                Err(BlockProofPolicyRejection::RecursiveBlockReceiptRootPayload)
            } else if input.has_block_artifact {
                Ok(())
            } else {
                Err(BlockProofPolicyRejection::MissingRecursiveBlockArtifact)
            }
        }
    }
}

fn proof_policy_rejection_to_error(
    rejection: BlockProofPolicyRejection,
    input: BlockProofPolicyInput,
) -> ProofError {
    match rejection {
        BlockProofPolicyRejection::EmptyBlockCarriesProof => ProofError::CommitmentProofEmptyBlock,
        BlockProofPolicyRejection::MissingTransactionProofs => ProofError::MissingTransactionProofs,
        BlockProofPolicyRejection::TransactionProofCountMismatch => {
            ProofError::TransactionProofCountMismatch {
                expected: input.tx_count,
                observed: input.tx_validity_artifact_count,
            }
        }
        BlockProofPolicyRejection::UnsupportedInlineRequired => ProofError::UnsupportedProofArtifact(
            "legacy InlineRequired block verification is no longer supported on the product path"
                .to_string(),
        ),
        BlockProofPolicyRejection::MissingProvenBatch => {
            ProofError::MissingProvenBatchForSelfContained
        }
        BlockProofPolicyRejection::MissingTransactionValidityClaims => {
            ProofError::MissingTransactionValidityClaims
        }
        BlockProofPolicyRejection::LegacyInlineBatch => ProofError::UnsupportedProofArtifact(
            "legacy InlineTx proven batches are no longer supported on the product path".to_string(),
        ),
        BlockProofPolicyRejection::RecursiveBlockCommitmentProofBytes => {
            ProofError::UnsupportedProofArtifact(
                "recursive block product lane forbids commitment proof bytes".to_string(),
            )
        }
        BlockProofPolicyRejection::RecursiveBlockReceiptRootPayload => {
            ProofError::ProvenBatchBindingMismatch(
                "recursive block proven batch must not carry receipt_root payload".to_string(),
            )
        }
        BlockProofPolicyRejection::MissingRecursiveBlockArtifact => {
            ProofError::MissingAggregationProofForSelfContainedMode
        }
        BlockProofPolicyRejection::MissingReceiptRootPayload => {
            ProofError::ProvenBatchBindingMismatch(
                "missing receipt_root payload for ReceiptRoot mode".to_string(),
            )
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeTxLeafAdmissionInput {
    has_envelope: bool,
    envelope_kind: ProofArtifactKind,
    envelope_verifier_profile_matches: bool,
    artifact_bytes_len: usize,
    max_artifact_bytes: usize,
    receipt_verifier_profile_matches: bool,
    has_expected_artifact_hash: bool,
    expected_artifact_hash_matches: bool,
    has_cache_entry: bool,
    cache_receipt_matches: bool,
    cache_transaction_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTxLeafAdmissionOutcome {
    NeedsBackendVerification,
    CacheHit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTxLeafAdmissionRejection {
    MissingEnvelope,
    ArtifactKindMismatch,
    EnvelopeVerifierProfileMismatch,
    ArtifactTooLarge,
    ReceiptVerifierProfileMismatch,
    ArtifactHashMismatch,
    CacheReceiptMismatch,
    CacheTransactionMismatch,
}

impl NativeTxLeafAdmissionOutcome {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::NeedsBackendVerification => "needs_backend_verification",
            Self::CacheHit => "cache_hit",
        }
    }
}

impl NativeTxLeafAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::MissingEnvelope => "missing_envelope",
            Self::ArtifactKindMismatch => "artifact_kind_mismatch",
            Self::EnvelopeVerifierProfileMismatch => "envelope_verifier_profile_mismatch",
            Self::ArtifactTooLarge => "artifact_too_large",
            Self::ReceiptVerifierProfileMismatch => "receipt_verifier_profile_mismatch",
            Self::ArtifactHashMismatch => "artifact_hash_mismatch",
            Self::CacheReceiptMismatch => "cache_receipt_mismatch",
            Self::CacheTransactionMismatch => "cache_transaction_mismatch",
        }
    }
}

fn evaluate_native_tx_leaf_admission(
    input: NativeTxLeafAdmissionInput,
) -> Result<NativeTxLeafAdmissionOutcome, NativeTxLeafAdmissionRejection> {
    if !input.has_envelope {
        return Err(NativeTxLeafAdmissionRejection::MissingEnvelope);
    }
    if input.envelope_kind != ProofArtifactKind::TxLeaf {
        return Err(NativeTxLeafAdmissionRejection::ArtifactKindMismatch);
    }
    if !input.envelope_verifier_profile_matches {
        return Err(NativeTxLeafAdmissionRejection::EnvelopeVerifierProfileMismatch);
    }
    if input.artifact_bytes_len > input.max_artifact_bytes {
        return Err(NativeTxLeafAdmissionRejection::ArtifactTooLarge);
    }
    if !input.receipt_verifier_profile_matches {
        return Err(NativeTxLeafAdmissionRejection::ReceiptVerifierProfileMismatch);
    }
    if input.has_expected_artifact_hash && !input.expected_artifact_hash_matches {
        return Err(NativeTxLeafAdmissionRejection::ArtifactHashMismatch);
    }
    if input.has_cache_entry {
        if !input.cache_receipt_matches {
            return Err(NativeTxLeafAdmissionRejection::CacheReceiptMismatch);
        }
        if !input.cache_transaction_matches {
            return Err(NativeTxLeafAdmissionRejection::CacheTransactionMismatch);
        }
        Ok(NativeTxLeafAdmissionOutcome::CacheHit)
    } else {
        Ok(NativeTxLeafAdmissionOutcome::NeedsBackendVerification)
    }
}

fn native_tx_leaf_admission_error(
    input: NativeTxLeafAdmissionInput,
    rejection: NativeTxLeafAdmissionRejection,
) -> ProofError {
    match rejection {
        NativeTxLeafAdmissionRejection::MissingEnvelope => ProofError::MissingTransactionProofs,
        NativeTxLeafAdmissionRejection::ArtifactKindMismatch => {
            ProofError::UnsupportedProofArtifact(format!(
                "expected tx_leaf proof envelope, got {}",
                input.envelope_kind.label()
            ))
        }
        NativeTxLeafAdmissionRejection::EnvelopeVerifierProfileMismatch => {
            ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: "native tx-leaf verifier profile mismatch".to_string(),
            }
        }
        NativeTxLeafAdmissionRejection::ArtifactTooLarge => {
            ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: format!(
                    "native tx-leaf artifact size {} exceeds {}",
                    input.artifact_bytes_len, input.max_artifact_bytes
                ),
            }
        }
        NativeTxLeafAdmissionRejection::ReceiptVerifierProfileMismatch => {
            ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: "native tx-leaf receipt verifier profile mismatch".to_string(),
            }
        }
        NativeTxLeafAdmissionRejection::ArtifactHashMismatch => {
            ProofError::AggregationProofInputsMismatch(
                "receipt accumulation artifact hash mismatch".to_string(),
            )
        }
        NativeTxLeafAdmissionRejection::CacheReceiptMismatch => {
            ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: "native tx-leaf cache entry receipt mismatch".to_string(),
            }
        }
        NativeTxLeafAdmissionRejection::CacheTransactionMismatch => {
            ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: "native tx-leaf cache entry transaction mismatch".to_string(),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReceiptRootPayloadAdmissionInput {
    payload_leaf_count_matches: bool,
    payload_receipt_count_matches: bool,
    has_claim_receipts: bool,
    payload_receipts_match_claims: bool,
    has_tx_artifacts: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptRootPayloadAdmissionRejection {
    LeafCountMismatch,
    ReceiptCountMismatch,
    MissingClaimReceipts,
    ReceiptsMismatch,
    MissingTransactionProofs,
}

impl ReceiptRootPayloadAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::LeafCountMismatch => "leaf_count_mismatch",
            Self::ReceiptCountMismatch => "receipt_count_mismatch",
            Self::MissingClaimReceipts => "missing_claim_receipts",
            Self::ReceiptsMismatch => "receipts_mismatch",
            Self::MissingTransactionProofs => "missing_transaction_proofs",
        }
    }
}

fn evaluate_receipt_root_payload_admission(
    input: ReceiptRootPayloadAdmissionInput,
) -> Result<(), ReceiptRootPayloadAdmissionRejection> {
    if !input.payload_leaf_count_matches {
        return Err(ReceiptRootPayloadAdmissionRejection::LeafCountMismatch);
    }
    if !input.payload_receipt_count_matches {
        return Err(ReceiptRootPayloadAdmissionRejection::ReceiptCountMismatch);
    }
    if !input.has_claim_receipts {
        return Err(ReceiptRootPayloadAdmissionRejection::MissingClaimReceipts);
    }
    if !input.payload_receipts_match_claims {
        return Err(ReceiptRootPayloadAdmissionRejection::ReceiptsMismatch);
    }
    if !input.has_tx_artifacts {
        return Err(ReceiptRootPayloadAdmissionRejection::MissingTransactionProofs);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReceiptRootArtifactAdmissionInput {
    envelope_kind: ProofArtifactKind,
    envelope_verifier_profile_matches: bool,
    artifact_bytes_len: usize,
    max_artifact_bytes: usize,
    has_tx_artifacts: bool,
    tx_artifact_count_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptRootArtifactAdmissionRejection {
    ArtifactKindMismatch,
    VerifierProfileMismatch,
    ArtifactTooLarge,
    MissingTransactionProofs,
    TransactionProofCountMismatch,
}

impl ReceiptRootArtifactAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ArtifactKindMismatch => "artifact_kind_mismatch",
            Self::VerifierProfileMismatch => "verifier_profile_mismatch",
            Self::ArtifactTooLarge => "artifact_too_large",
            Self::MissingTransactionProofs => "missing_transaction_proofs",
            Self::TransactionProofCountMismatch => "transaction_proof_count_mismatch",
        }
    }
}

fn evaluate_receipt_root_artifact_admission(
    input: ReceiptRootArtifactAdmissionInput,
) -> Result<(), ReceiptRootArtifactAdmissionRejection> {
    if input.envelope_kind != ProofArtifactKind::ReceiptRoot {
        return Err(ReceiptRootArtifactAdmissionRejection::ArtifactKindMismatch);
    }
    if !input.envelope_verifier_profile_matches {
        return Err(ReceiptRootArtifactAdmissionRejection::VerifierProfileMismatch);
    }
    if input.artifact_bytes_len > input.max_artifact_bytes {
        return Err(ReceiptRootArtifactAdmissionRejection::ArtifactTooLarge);
    }
    if !input.has_tx_artifacts {
        return Err(ReceiptRootArtifactAdmissionRejection::MissingTransactionProofs);
    }
    if !input.tx_artifact_count_matches {
        return Err(ReceiptRootArtifactAdmissionRejection::TransactionProofCountMismatch);
    }
    Ok(())
}

fn receipt_root_artifact_admission_error(
    input: ReceiptRootArtifactAdmissionInput,
    tx_count: usize,
    tx_artifact_count: usize,
    rejection: ReceiptRootArtifactAdmissionRejection,
) -> ProofError {
    match rejection {
        ReceiptRootArtifactAdmissionRejection::ArtifactKindMismatch => {
            ProofError::UnsupportedProofArtifact(format!(
                "expected {} block artifact, got {}",
                ProofArtifactKind::ReceiptRoot.label(),
                input.envelope_kind.label()
            ))
        }
        ReceiptRootArtifactAdmissionRejection::VerifierProfileMismatch => {
            ProofError::AggregationProofInputsMismatch(
                "receipt-root requires the native verifier profile".to_string(),
            )
        }
        ReceiptRootArtifactAdmissionRejection::ArtifactTooLarge => {
            ProofError::AggregationProofInputsMismatch(format!(
                "native receipt-root artifact size {} exceeds {} for tx_count {}",
                input.artifact_bytes_len, input.max_artifact_bytes, tx_count
            ))
        }
        ReceiptRootArtifactAdmissionRejection::MissingTransactionProofs => {
            ProofError::MissingTransactionProofs
        }
        ReceiptRootArtifactAdmissionRejection::TransactionProofCountMismatch => {
            ProofError::TransactionProofCountMismatch {
                expected: tx_count,
                observed: tx_artifact_count,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReceiptRootStatementBindingInput {
    statement_commitment_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptRootStatementBindingRejection {
    StatementCommitmentMismatch,
}

impl ReceiptRootStatementBindingRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::StatementCommitmentMismatch => "statement_commitment_mismatch",
        }
    }
}

fn evaluate_receipt_root_statement_binding(
    input: ReceiptRootStatementBindingInput,
) -> Result<(), ReceiptRootStatementBindingRejection> {
    if input.statement_commitment_matches {
        Ok(())
    } else {
        Err(ReceiptRootStatementBindingRejection::StatementCommitmentMismatch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReceiptRootVerifiedMetadataInput {
    verified_leaf_count_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptRootVerifiedMetadataRejection {
    VerifiedLeafCountMismatch,
}

impl ReceiptRootVerifiedMetadataRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::VerifiedLeafCountMismatch => "verified_leaf_count_mismatch",
        }
    }
}

fn evaluate_receipt_root_verified_metadata(
    input: ReceiptRootVerifiedMetadataInput,
) -> Result<(), ReceiptRootVerifiedMetadataRejection> {
    if input.verified_leaf_count_matches {
        Ok(())
    } else {
        Err(ReceiptRootVerifiedMetadataRejection::VerifiedLeafCountMismatch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecursiveBlockArtifactAdmissionInput {
    expected_kind: ProofArtifactKind,
    envelope_kind: ProofArtifactKind,
    verifier_profile_matches: bool,
    artifact_bytes_len: usize,
    max_artifact_bytes: usize,
    artifact_decoded: bool,
    header_version_matches: bool,
    tx_count_matches: bool,
    statement_commitment_matches: bool,
    public_replay_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecursiveBlockArtifactAdmissionRejection {
    ArtifactKindMismatch,
    VerifierProfileMismatch,
    ArtifactTooLarge,
    ArtifactDecodeFailed,
    HeaderVersionMismatch,
    TxCountMismatch,
    StatementCommitmentMismatch,
    PublicReplayMismatch,
}

impl RecursiveBlockArtifactAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ArtifactKindMismatch => "artifact_kind_mismatch",
            Self::VerifierProfileMismatch => "verifier_profile_mismatch",
            Self::ArtifactTooLarge => "artifact_too_large",
            Self::ArtifactDecodeFailed => "artifact_decode_failed",
            Self::HeaderVersionMismatch => "header_version_mismatch",
            Self::TxCountMismatch => "tx_count_mismatch",
            Self::StatementCommitmentMismatch => "statement_commitment_mismatch",
            Self::PublicReplayMismatch => "public_replay_mismatch",
        }
    }
}

fn evaluate_recursive_block_artifact_admission(
    input: RecursiveBlockArtifactAdmissionInput,
) -> Result<(), RecursiveBlockArtifactAdmissionRejection> {
    if input.envelope_kind != input.expected_kind {
        return Err(RecursiveBlockArtifactAdmissionRejection::ArtifactKindMismatch);
    }
    if !input.verifier_profile_matches {
        return Err(RecursiveBlockArtifactAdmissionRejection::VerifierProfileMismatch);
    }
    if input.artifact_bytes_len > input.max_artifact_bytes {
        return Err(RecursiveBlockArtifactAdmissionRejection::ArtifactTooLarge);
    }
    if !input.artifact_decoded {
        return Err(RecursiveBlockArtifactAdmissionRejection::ArtifactDecodeFailed);
    }
    if !input.header_version_matches {
        return Err(RecursiveBlockArtifactAdmissionRejection::HeaderVersionMismatch);
    }
    if !input.tx_count_matches {
        return Err(RecursiveBlockArtifactAdmissionRejection::TxCountMismatch);
    }
    if !input.statement_commitment_matches {
        return Err(RecursiveBlockArtifactAdmissionRejection::StatementCommitmentMismatch);
    }
    if !input.public_replay_matches {
        return Err(RecursiveBlockArtifactAdmissionRejection::PublicReplayMismatch);
    }
    Ok(())
}

fn recursive_block_admission_input_for_predecode(
    expected_kind: ProofArtifactKind,
    envelope: &ProofEnvelope,
    verifier_profile_matches: bool,
) -> RecursiveBlockArtifactAdmissionInput {
    let max_artifact_bytes = match expected_kind {
        ProofArtifactKind::RecursiveBlockV1 => RECURSIVE_BLOCK_V1_ARTIFACT_MAX_BYTES,
        ProofArtifactKind::RecursiveBlockV2 => RECURSIVE_BLOCK_V2_ARTIFACT_MAX_BYTES,
        _ => 0,
    };
    RecursiveBlockArtifactAdmissionInput {
        expected_kind,
        envelope_kind: envelope.kind,
        verifier_profile_matches,
        artifact_bytes_len: envelope.artifact_bytes.len(),
        max_artifact_bytes,
        artifact_decoded: true,
        header_version_matches: true,
        tx_count_matches: true,
        statement_commitment_matches: true,
        public_replay_matches: true,
    }
}

fn recursive_block_decode_admission_input(
    mut input: RecursiveBlockArtifactAdmissionInput,
) -> RecursiveBlockArtifactAdmissionInput {
    input.artifact_decoded = false;
    input
}

fn recursive_block_admission_error(
    label: &'static str,
    input: RecursiveBlockArtifactAdmissionInput,
    tx_count: usize,
    payload_tx_count: Option<u32>,
    header_version: Option<u32>,
    decode_error: Option<String>,
    rejection: RecursiveBlockArtifactAdmissionRejection,
) -> ProofError {
    match rejection {
        RecursiveBlockArtifactAdmissionRejection::ArtifactKindMismatch => {
            ProofError::UnsupportedProofArtifact(format!(
                "expected {} block artifact, got {}",
                input.expected_kind.label(),
                input.envelope_kind.label()
            ))
        }
        RecursiveBlockArtifactAdmissionRejection::VerifierProfileMismatch => {
            let version = match input.expected_kind {
                ProofArtifactKind::RecursiveBlockV1 => "v1",
                ProofArtifactKind::RecursiveBlockV2 => "v2",
                _ => label,
            };
            ProofError::AggregationProofInputsMismatch(format!(
                "{label} requires the {version} verifier profile"
            ))
        }
        RecursiveBlockArtifactAdmissionRejection::ArtifactTooLarge => {
            ProofError::AggregationProofInputsMismatch(format!(
                "{label} artifact size {} exceeds {}",
                input.artifact_bytes_len, input.max_artifact_bytes
            ))
        }
        RecursiveBlockArtifactAdmissionRejection::ArtifactDecodeFailed => {
            ProofError::AggregationProofVerification(format!(
                "{label} artifact decode failed: {}",
                decode_error.unwrap_or_else(|| "unknown decode error".to_string())
            ))
        }
        RecursiveBlockArtifactAdmissionRejection::HeaderVersionMismatch => {
            ProofError::AggregationProofInputsMismatch(format!(
                "{label} header version mismatch: {}",
                header_version.unwrap_or(0)
            ))
        }
        RecursiveBlockArtifactAdmissionRejection::TxCountMismatch => {
            ProofError::AggregationProofInputsMismatch(format!(
                "{label} tx_count mismatch (payload {}, expected {})",
                payload_tx_count.unwrap_or(0),
                tx_count
            ))
        }
        RecursiveBlockArtifactAdmissionRejection::StatementCommitmentMismatch => {
            ProofError::AggregationProofInputsMismatch(format!(
                "{label} statement commitment mismatch"
            ))
        }
        RecursiveBlockArtifactAdmissionRejection::PublicReplayMismatch => {
            ProofError::AggregationProofInputsMismatch(format!("{label} public replay mismatch"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedNativeTxLeaf {
    tx: TxLeafPublicTx,
    receipt: TxValidityReceipt,
    binding: TxStatementBinding,
    leaf: NativeTxLeafRecord,
}

fn recursive_block_leaf_record_from_verified(
    tx_index: u32,
    record: &VerifiedNativeTxLeaf,
) -> BlockLeafRecordV1 {
    BlockLeafRecordV1 {
        tx_index,
        receipt_statement_hash: record.receipt.statement_hash,
        receipt_proof_digest: record.receipt.proof_digest,
        receipt_public_inputs_digest: record.receipt.public_inputs_digest,
        receipt_verifier_profile: record.receipt.verifier_profile,
        leaf_params_fingerprint: record.leaf.params_fingerprint,
        leaf_spec_digest: record.leaf.spec_digest,
        leaf_relation_id: record.leaf.relation_id,
        leaf_shape_digest: record.leaf.shape_digest,
        leaf_statement_digest: record.leaf.statement_digest,
        leaf_commitment_digest: record.leaf.commitment.digest,
        leaf_proof_digest: record.leaf.proof_digest,
    }
}

fn verify_recursive_block_artifact_against_verified_records(
    txs: &[crate::types::Transaction],
    artifacts: &[TxValidityArtifact],
    expected_commitment: &[u8; 48],
    semantic: &BlockSemanticInputsV1,
    envelope: &ProofEnvelope,
) -> Result<BlockArtifactVerifyReport, ProofError> {
    let verified_records = verify_native_tx_leaf_artifact_records(txs, artifacts)?;
    let block_records = verified_records
        .iter()
        .enumerate()
        .map(|(tx_index, record)| {
            recursive_block_leaf_record_from_verified(tx_index as u32, record)
        })
        .collect::<Vec<_>>();
    let start_verify = Instant::now();
    match envelope.kind {
        ProofArtifactKind::RecursiveBlockV1 => {
            let label = ProofArtifactKind::RecursiveBlockV1.label();
            let admission_input = recursive_block_admission_input_for_predecode(
                ProofArtifactKind::RecursiveBlockV1,
                envelope,
                envelope.verifier_profile == backend_recursive_block_profile_v1(),
            );
            evaluate_recursive_block_artifact_admission(admission_input).map_err(|rejection| {
                recursive_block_admission_error(
                    label,
                    admission_input,
                    txs.len(),
                    None,
                    None,
                    None,
                    rejection,
                )
            })?;
            let parsed = match deserialize_recursive_block_artifact_v1(&envelope.artifact_bytes) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let decode_input = recursive_block_decode_admission_input(admission_input);
                    let rejection = evaluate_recursive_block_artifact_admission(decode_input)
                        .expect_err("recursive block decode admission must reject failed decode");
                    return Err(recursive_block_admission_error(
                        label,
                        decode_input,
                        txs.len(),
                        None,
                        None,
                        Some(err.to_string()),
                        rejection,
                    ));
                }
            };
            let decoded_input = RecursiveBlockArtifactAdmissionInput {
                header_version_matches: parsed.artifact.header.artifact_version_rec
                    == RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
                tx_count_matches: parsed.public.tx_count as usize == txs.len(),
                statement_commitment_matches: parsed.public.tx_statements_commitment
                    == *expected_commitment,
                ..admission_input
            };
            evaluate_recursive_block_artifact_admission(decoded_input).map_err(|rejection| {
                recursive_block_admission_error(
                    label,
                    decoded_input,
                    txs.len(),
                    Some(parsed.public.tx_count),
                    Some(parsed.artifact.header.artifact_version_rec),
                    None,
                    rejection,
                )
            })?;
            let expected_public = public_replay_v1(&block_records, semantic).map_err(|err| {
                ProofError::AggregationProofVerification(format!(
                    "recursive_block_v1 public replay failed: {err}"
                ))
            })?;
            let replay_input = RecursiveBlockArtifactAdmissionInput {
                public_replay_matches: parsed.public == expected_public,
                ..decoded_input
            };
            evaluate_recursive_block_artifact_admission(replay_input).map_err(|rejection| {
                recursive_block_admission_error(
                    label,
                    replay_input,
                    txs.len(),
                    Some(parsed.public.tx_count),
                    Some(parsed.artifact.header.artifact_version_rec),
                    None,
                    rejection,
                )
            })?;
            verify_block_recursive_v1(&parsed, &expected_public).map_err(|err| {
                ProofError::AggregationProofVerification(format!(
                    "recursive_block_v1 verification failed: {err}"
                ))
            })?;
            Ok(BlockArtifactVerifyReport {
                tx_count: txs.len(),
                verified_statement_commitment: *expected_commitment,
                verify_ms: start_verify.elapsed().as_millis(),
                verify_batch_ms: 0,
                cache_hit: None,
                cache_build_ms: None,
                root_verify_mode: Some(ProofArtifactKind::RecursiveBlockV1.label()),
            })
        }
        ProofArtifactKind::RecursiveBlockV2 => {
            let label = ProofArtifactKind::RecursiveBlockV2.label();
            let admission_input = recursive_block_admission_input_for_predecode(
                ProofArtifactKind::RecursiveBlockV2,
                envelope,
                envelope.verifier_profile == backend_recursive_block_profile_v2(),
            );
            evaluate_recursive_block_artifact_admission(admission_input).map_err(|rejection| {
                recursive_block_admission_error(
                    label,
                    admission_input,
                    txs.len(),
                    None,
                    None,
                    None,
                    rejection,
                )
            })?;
            let parsed = match deserialize_recursive_block_artifact_v2(&envelope.artifact_bytes) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let decode_input = recursive_block_decode_admission_input(admission_input);
                    let rejection = evaluate_recursive_block_artifact_admission(decode_input)
                        .expect_err("recursive block decode admission must reject failed decode");
                    return Err(recursive_block_admission_error(
                        label,
                        decode_input,
                        txs.len(),
                        None,
                        None,
                        Some(err.to_string()),
                        rejection,
                    ));
                }
            };
            let decoded_input = RecursiveBlockArtifactAdmissionInput {
                header_version_matches: parsed.artifact.header.artifact_version_rec
                    == RECURSIVE_BLOCK_ARTIFACT_VERSION_V2,
                tx_count_matches: parsed.public.tx_count as usize == txs.len(),
                statement_commitment_matches: parsed.public.tx_statements_commitment
                    == *expected_commitment,
                ..admission_input
            };
            evaluate_recursive_block_artifact_admission(decoded_input).map_err(|rejection| {
                recursive_block_admission_error(
                    label,
                    decoded_input,
                    txs.len(),
                    Some(parsed.public.tx_count),
                    Some(parsed.artifact.header.artifact_version_rec),
                    None,
                    rejection,
                )
            })?;
            let expected_public = public_replay_v2(&block_records, semantic).map_err(|err| {
                ProofError::AggregationProofVerification(format!(
                    "recursive_block_v2 public replay failed: {err}"
                ))
            })?;
            let replay_input = RecursiveBlockArtifactAdmissionInput {
                public_replay_matches: parsed.public == expected_public,
                ..decoded_input
            };
            evaluate_recursive_block_artifact_admission(replay_input).map_err(|rejection| {
                recursive_block_admission_error(
                    label,
                    replay_input,
                    txs.len(),
                    Some(parsed.public.tx_count),
                    Some(parsed.artifact.header.artifact_version_rec),
                    None,
                    rejection,
                )
            })?;
            verify_block_recursive_v2(&parsed, &expected_public).map_err(|err| {
                ProofError::AggregationProofVerification(format!(
                    "recursive_block_v2 verification failed: {err}"
                ))
            })?;
            Ok(BlockArtifactVerifyReport {
                tx_count: txs.len(),
                verified_statement_commitment: *expected_commitment,
                verify_ms: start_verify.elapsed().as_millis(),
                verify_batch_ms: 0,
                cache_hit: None,
                cache_build_ms: None,
                root_verify_mode: Some(ProofArtifactKind::RecursiveBlockV2.label()),
            })
        }
        _ => Err(ProofError::UnsupportedProofArtifact(format!(
            "expected recursive_block_v1 or recursive_block_v2 artifact, got {}",
            envelope.kind.label()
        ))),
    }
}

pub fn build_recursive_block_v2_artifact_for_native_txs<BH>(
    block: &Block<BH>,
    artifacts: &[TxValidityArtifact],
    parent_commitment_tree: &CommitmentTreeState,
) -> Result<RecursiveBlockV2ArtifactBuild, ProofError>
where
    BH: HeaderProofExt,
{
    verify_commitments(block)?;
    if block.transactions.is_empty() {
        return Err(ProofError::ProvenBatchBindingMismatch(
            "recursive block artifact requires at least one transaction".to_string(),
        ));
    }
    if artifacts.len() != block.transactions.len() {
        return Err(ProofError::TransactionProofCountMismatch {
            expected: block.transactions.len(),
            observed: artifacts.len(),
        });
    }

    let claims = tx_validity_claims_from_tx_artifacts(&block.transactions, artifacts)?;
    let statement_bindings = tx_statement_bindings_from_claims(&claims)?;
    validate_statement_anchor_history(
        parent_commitment_tree,
        block.transactions.len(),
        &statement_bindings,
    )?;
    let tx_statements_commitment = commitment_from_statement_bindings(&statement_bindings)?;
    if let Some(expected) = block.tx_statements_commitment
        && expected != tx_statements_commitment
    {
        return Err(ProofError::CommitmentProofInputsMismatch(
            "tx_statements_commitment does not match native tx artifacts".to_string(),
        ));
    }

    let verified_records = verify_native_tx_leaf_artifact_records(&block.transactions, artifacts)?;
    let records = verified_records
        .iter()
        .enumerate()
        .map(|(tx_index, record)| {
            recursive_block_leaf_record_from_verified(tx_index as u32, record)
        })
        .collect::<Vec<_>>();
    let semantic = recursive_block_semantic_inputs_from_block(
        block,
        parent_commitment_tree,
        tx_statements_commitment,
    )?;
    let recursive = crate::backend_interface::prove_block_recursive_v2(
        &crate::backend_interface::BlockRecursiveProverInputV2 { records, semantic },
    )
    .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    let artifact_bytes =
        crate::backend_interface::serialize_recursive_block_artifact_v2(&recursive)
            .map_err(|err| ProofError::AggregationProofVerification(err.to_string()))?;
    let da_encoding = crate::types::encode_da_blob(&block.transactions, block.header.da_params())
        .map_err(|err| ProofError::DaEncoding(err.to_string()))?;
    let da_chunk_count = u32::try_from(da_encoding.chunks().len())
        .map_err(|_| ProofError::DaEncoding("DA chunk count exceeds u32".to_string()))?;

    Ok(RecursiveBlockV2ArtifactBuild {
        artifact_bytes,
        tx_count: block.transactions.len() as u32,
        tx_statements_commitment,
        da_root: da_encoding.root(),
        da_chunk_count,
        verifier_profile: backend_recursive_block_profile_v2(),
    })
}

fn recursive_block_semantic_inputs_from_block(
    block: &Block<impl HeaderProofExt>,
    parent_commitment_tree: &CommitmentTreeState,
    expected_commitment: [u8; 48],
) -> Result<BlockSemanticInputsV1, ProofError> {
    let nullifier_lists = commitment_nullifier_lists(&block.transactions)?;
    let expected_tree = apply_commitments(parent_commitment_tree, &block.transactions)?;
    let start_shielded_root = parent_commitment_tree.root();
    let end_shielded_root = expected_tree.root();
    let start_kernel_root = kernel_root_from_shielded_root(&start_shielded_root);
    let end_kernel_root = kernel_root_from_shielded_root(&end_shielded_root);
    let nullifier_root = nullifier_root_from_list(&nullifier_lists.nullifiers)?;
    let da_root = da_root(&block.transactions, block.header.da_params())
        .map_err(|err| ProofError::DaEncoding(err.to_string()))?;

    Ok(BlockSemanticInputsV1 {
        tx_statements_commitment: expected_commitment,
        start_shielded_root,
        end_shielded_root,
        start_kernel_root,
        end_kernel_root,
        nullifier_root,
        da_root,
        message_root: block.header.message_root(),
        start_tree_commitment: parent_commitment_tree.recursive_state_commitment(),
        end_tree_commitment: expected_tree.recursive_state_commitment(),
    })
}

struct NativeTxLeafVerifyCache {
    capacity: usize,
    order: VecDeque<[u8; 48]>,
    entries: HashMap<[u8; 48], VerifiedNativeTxLeaf>,
}

impl NativeTxLeafVerifyCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn get(&mut self, key: [u8; 48]) -> Option<VerifiedNativeTxLeaf> {
        let value = self.entries.get(&key).cloned();
        if value.is_some() {
            self.order.retain(|entry| entry != &key);
            self.order.push_back(key);
        }
        value
    }

    fn insert(&mut self, key: [u8; 48], value: VerifiedNativeTxLeaf) {
        if self.capacity == 0 {
            return;
        }
        if let Some(existing) = self.entries.get_mut(&key) {
            *existing = value;
            self.order.retain(|entry| entry != &key);
            self.order.push_back(key);
            return;
        }
        while self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        self.entries.insert(key, value);
        self.order.push_back(key);
    }
}

fn load_native_tx_leaf_verify_cache_capacity() -> usize {
    std::env::var("HEGEMON_NATIVE_TX_LEAF_VERIFY_CACHE_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|capacity| *capacity > 0)
        .unwrap_or(DEFAULT_NATIVE_TX_LEAF_VERIFY_CACHE_CAPACITY)
}

static NATIVE_TX_LEAF_VERIFY_CACHE: LazyLock<Mutex<NativeTxLeafVerifyCache>> =
    LazyLock::new(|| {
        Mutex::new(NativeTxLeafVerifyCache::new(
            load_native_tx_leaf_verify_cache_capacity(),
        ))
    });

fn native_tx_leaf_artifact_hash(artifact_bytes: &[u8]) -> [u8; 48] {
    blake3_384(artifact_bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockArtifactVerifyReport {
    pub tx_count: usize,
    pub verified_statement_commitment: [u8; 48],
    pub verify_ms: u128,
    pub verify_batch_ms: u128,
    pub cache_hit: Option<bool>,
    pub cache_build_ms: Option<u128>,
    pub root_verify_mode: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveBlockV2ArtifactBuild {
    pub artifact_bytes: Vec<u8>,
    pub tx_count: u32,
    pub tx_statements_commitment: [u8; 48],
    pub da_root: [u8; 48],
    pub da_chunk_count: u32,
    pub verifier_profile: VerifierProfileDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeReceiptRootVerifyMode {
    Replay,
    VerifiedRecords,
    CrossCheck,
}

impl NativeReceiptRootVerifyMode {
    fn label(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::VerifiedRecords => "verified_records",
            Self::CrossCheck => "cross_check",
        }
    }
}

fn load_native_receipt_root_verify_mode() -> NativeReceiptRootVerifyMode {
    let Some(raw) = std::env::var("HEGEMON_NATIVE_RECEIPT_ROOT_VERIFY_MODE").ok() else {
        return NativeReceiptRootVerifyMode::VerifiedRecords;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "verified_records" | "verified-records" | "records" => {
            NativeReceiptRootVerifyMode::VerifiedRecords
        }
        "replay" => NativeReceiptRootVerifyMode::Replay,
        "cross_check" | "cross-check" | "crosscheck" => NativeReceiptRootVerifyMode::CrossCheck,
        other => {
            tracing::warn!(
                value = other,
                "unrecognized HEGEMON_NATIVE_RECEIPT_ROOT_VERIFY_MODE; defaulting to verified_records"
            );
            NativeReceiptRootVerifyMode::VerifiedRecords
        }
    }
}

pub fn native_receipt_root_verify_mode_label() -> &'static str {
    load_native_receipt_root_verify_mode().label()
}

#[cfg(test)]
type ReceiptRootBackendOverride = Arc<
    dyn Fn(
            &[NativeTxLeafRecord],
            &[TxValidityArtifact],
            &[u8],
        ) -> Result<crate::types::ReceiptRootMetadata, ProofError>
        + Send
        + Sync,
>;

#[cfg(test)]
thread_local! {
    static RECEIPT_ROOT_BACKEND_OVERRIDE: std::cell::RefCell<Option<ReceiptRootBackendOverride>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn receipt_root_backend_override_result(
    leaf_records: &[NativeTxLeafRecord],
    artifacts: &[TxValidityArtifact],
    artifact_bytes: &[u8],
) -> Option<Result<crate::types::ReceiptRootMetadata, ProofError>> {
    RECEIPT_ROOT_BACKEND_OVERRIDE.with(|override_cell| {
        override_cell
            .borrow()
            .as_ref()
            .map(|override_fn| override_fn(leaf_records, artifacts, artifact_bytes))
    })
}

pub trait ArtifactVerifier: Send + Sync {
    fn kind(&self) -> ProofArtifactKind;
    fn supports_verifier_profile(&self, verifier_profile: VerifierProfileDigest) -> bool;

    fn verify_tx_artifact(
        &self,
        _tx: &crate::types::Transaction,
        _artifact: &TxValidityArtifact,
    ) -> Result<TxStatementBinding, ProofError> {
        Err(ProofError::UnsupportedProofArtifact(format!(
            "proof kind {} does not support tx-artifact verification",
            self.kind().label()
        )))
    }

    fn verify_block_artifact(
        &self,
        _txs: &[crate::types::Transaction],
        _tx_artifacts: Option<&[TxValidityArtifact]>,
        _expected_commitment: &[u8; 48],
        _envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError> {
        Err(ProofError::UnsupportedProofArtifact(format!(
            "proof kind {} does not support block-artifact verification",
            self.kind().label()
        )))
    }
}

#[derive(Clone)]
pub struct VerifierRegistry {
    verifiers: Vec<Arc<dyn ArtifactVerifier>>,
}

impl Default for VerifierRegistry {
    fn default() -> Self {
        let mut registry = Self {
            verifiers: Vec::new(),
        };
        registry.register(Arc::new(InlineTxP3Verifier {
            verifying_key: generate_keys().1,
        }));
        registry.register(Arc::new(TxLeafVerifier));
        registry.register(Arc::new(NativeTxLeafVerifier));
        registry.register(Arc::new(ReceiptRootVerifier));
        registry.register(Arc::new(RecursiveBlockVerifier {
            kind: ProofArtifactKind::RecursiveBlockV1,
        }));
        registry.register(Arc::new(RecursiveBlockVerifier {
            kind: ProofArtifactKind::RecursiveBlockV2,
        }));
        registry
    }
}

impl VerifierRegistry {
    pub fn register(&mut self, verifier: Arc<dyn ArtifactVerifier>) {
        self.verifiers.push(verifier);
    }

    pub fn resolve(
        &self,
        kind: ProofArtifactKind,
        verifier_profile: VerifierProfileDigest,
    ) -> Result<&dyn ArtifactVerifier, ProofError> {
        self.verifiers
            .iter()
            .find(|verifier| {
                verifier.kind() == kind && verifier.supports_verifier_profile(verifier_profile)
            })
            .map(|verifier| verifier.as_ref())
            .ok_or_else(|| {
                ProofError::MissingArtifactVerifier(format!(
                    "kind={} verifier_profile=0x{} has no registered verifier",
                    kind.label(),
                    hex::encode(verifier_profile)
                ))
            })
    }
}

struct InlineTxP3Verifier {
    verifying_key: transaction_circuit::keys::VerifyingKey,
}

impl ArtifactVerifier for InlineTxP3Verifier {
    fn kind(&self) -> ProofArtifactKind {
        ProofArtifactKind::InlineTx
    }

    fn supports_verifier_profile(&self, verifier_profile: VerifierProfileDigest) -> bool {
        verifier_profile != [0u8; 48]
    }

    fn verify_tx_artifact(
        &self,
        tx: &crate::types::Transaction,
        artifact: &TxValidityArtifact,
    ) -> Result<TxStatementBinding, ProofError> {
        let proof = decode_inline_tx_artifact_proof(artifact)?;
        let expected_profile = transaction_verifier_profile_digest_for_version(tx.version);
        if artifact.receipt.verifier_profile != expected_profile {
            return Err(ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: "verifier profile mismatch".to_string(),
            });
        }
        let envelope = artifact
            .proof
            .as_ref()
            .ok_or(ProofError::MissingTransactionProofs)?;
        if envelope.verifier_profile != expected_profile {
            return Err(ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: "proof envelope verifier profile mismatch".to_string(),
            });
        }
        let expected_receipt = tx_validity_receipt_from_proof(&proof)
            .map_err(|message| ProofError::TransactionProofInputsMismatch { index: 0, message })?;
        if expected_receipt != artifact.receipt {
            return Err(ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: "tx validity receipt mismatch".to_string(),
            });
        }
        verify_transaction_proof_inputs_unindexed(tx, &proof)
            .map_err(|message| ProofError::TransactionProofInputsMismatch { index: 0, message })?;
        verify_transaction_proof_unindexed(&self.verifying_key, &proof)
            .map_err(|message| ProofError::TransactionProofVerification { index: 0, message })?;
        Ok(statement_binding_from_proof(&proof))
    }
}

struct TxLeafVerifier;

impl ArtifactVerifier for TxLeafVerifier {
    fn kind(&self) -> ProofArtifactKind {
        ProofArtifactKind::TxLeaf
    }

    fn supports_verifier_profile(&self, verifier_profile: VerifierProfileDigest) -> bool {
        verifier_profile == experimental_tx_leaf_verifier_profile()
    }

    fn verify_tx_artifact(
        &self,
        tx: &crate::types::Transaction,
        artifact: &TxValidityArtifact,
    ) -> Result<TxStatementBinding, ProofError> {
        let envelope = artifact
            .proof
            .as_ref()
            .ok_or(ProofError::MissingTransactionProofs)?;
        if envelope.kind != self.kind() {
            return Err(ProofError::UnsupportedProofArtifact(format!(
                "expected {} proof envelope, got {}",
                self.kind().label(),
                envelope.kind.label()
            )));
        }
        if envelope.verifier_profile != experimental_tx_leaf_verifier_profile() {
            return Err(ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: "tx-leaf verifier profile mismatch".to_string(),
            });
        }
        let expected_profile = transaction_verifier_profile_digest_for_version(tx.version);
        if artifact.receipt.verifier_profile != expected_profile {
            return Err(ProofError::TransactionProofInputsMismatch {
                index: 0,
                message: "tx-leaf tx verifier profile mismatch".to_string(),
            });
        }
        let canonical = canonical_receipt_from_tx_receipt(&artifact.receipt);
        let tx_view = tx_leaf_public_tx_from_consensus_tx(tx);
        let metadata =
            verify_tx_leaf_artifact_bytes(&tx_view, &canonical, &envelope.artifact_bytes).map_err(
                |err| ProofError::TransactionProofVerification {
                    index: 0,
                    message: format!("tx-leaf verification failed: {err}"),
                },
            )?;
        statement_binding_from_tx_leaf(tx, &artifact.receipt, &metadata.stark_public_inputs)
            .map_err(|message| ProofError::TransactionProofInputsMismatch { index: 0, message })
    }
}

struct NativeTxLeafVerifier;

fn verify_native_tx_leaf_artifact_record(
    tx: &crate::types::Transaction,
    artifact: &TxValidityArtifact,
    expected_hash: Option<[u8; 48]>,
) -> Result<VerifiedNativeTxLeaf, ProofError> {
    let envelope = artifact.proof.as_ref();
    let native_profile = experimental_native_tx_leaf_verifier_profile();
    let max_artifact_bytes = max_native_tx_leaf_artifact_bytes();
    let tx_view = tx_leaf_public_tx_from_consensus_tx(tx);
    let artifact_hash = envelope.and_then(|envelope| {
        let cheap_checks_pass = envelope.kind == ProofArtifactKind::TxLeaf
            && envelope.verifier_profile == native_profile
            && envelope.artifact_bytes.len() <= max_artifact_bytes
            && artifact.receipt.verifier_profile == native_profile;
        cheap_checks_pass.then(|| native_tx_leaf_artifact_hash(&envelope.artifact_bytes))
    });
    let cached_record = artifact_hash.and_then(|hash| NATIVE_TX_LEAF_VERIFY_CACHE.lock().get(hash));
    let admission_input = NativeTxLeafAdmissionInput {
        has_envelope: envelope.is_some(),
        envelope_kind: envelope
            .map(|envelope| envelope.kind)
            .unwrap_or(ProofArtifactKind::InlineTx),
        envelope_verifier_profile_matches: envelope
            .map(|envelope| envelope.verifier_profile == native_profile)
            .unwrap_or(false),
        artifact_bytes_len: envelope
            .map(|envelope| envelope.artifact_bytes.len())
            .unwrap_or(0),
        max_artifact_bytes,
        receipt_verifier_profile_matches: artifact.receipt.verifier_profile == native_profile,
        has_expected_artifact_hash: expected_hash.is_some(),
        expected_artifact_hash_matches: match (expected_hash, artifact_hash) {
            (Some(expected), Some(observed)) => expected == observed,
            (Some(_), None) => false,
            (None, _) => true,
        },
        has_cache_entry: cached_record.is_some(),
        cache_receipt_matches: cached_record
            .as_ref()
            .map(|record| record.receipt == artifact.receipt)
            .unwrap_or(true),
        cache_transaction_matches: cached_record
            .as_ref()
            .map(|record| record.tx == tx_view)
            .unwrap_or(true),
    };
    let admission = evaluate_native_tx_leaf_admission(admission_input)
        .map_err(|rejection| native_tx_leaf_admission_error(admission_input, rejection))?;
    if admission == NativeTxLeafAdmissionOutcome::CacheHit {
        return Ok(cached_record.expect("cache-hit admission has cached record"));
    }
    let envelope = envelope.expect("native tx-leaf admission requires an envelope");
    let artifact_hash = artifact_hash.expect("native tx-leaf admission requires artifact hash");

    let canonical = canonical_receipt_from_tx_receipt(&artifact.receipt);
    let metadata =
        verify_native_tx_leaf_artifact_bytes(&tx_view, &canonical, &envelope.artifact_bytes)
            .map_err(|err| ProofError::TransactionProofVerification {
                index: 0,
                message: format!("native tx-leaf verification failed: {err}"),
            })?;
    let binding =
        statement_binding_from_tx_leaf(tx, &artifact.receipt, &metadata.stark_public_inputs)
            .map_err(|message| ProofError::TransactionProofInputsMismatch { index: 0, message })?;
    let decoded =
        decode_native_tx_leaf_artifact_bytes(&envelope.artifact_bytes).map_err(|err| {
            ProofError::TransactionProofVerification {
                index: 0,
                message: format!("failed to decode native tx-leaf artifact: {err}"),
            }
        })?;
    let record = VerifiedNativeTxLeaf {
        tx: tx_view,
        receipt: artifact.receipt.clone(),
        binding,
        leaf: native_tx_leaf_record_from_artifact(&decoded),
    };
    NATIVE_TX_LEAF_VERIFY_CACHE
        .lock()
        .insert(artifact_hash, record.clone());
    Ok(record)
}

fn verify_native_tx_leaf_artifact_records(
    transactions: &[crate::types::Transaction],
    artifacts: &[TxValidityArtifact],
) -> Result<Vec<VerifiedNativeTxLeaf>, ProofError> {
    if artifacts.len() != transactions.len() {
        return Err(ProofError::TransactionProofCountMismatch {
            expected: transactions.len(),
            observed: artifacts.len(),
        });
    }

    transactions
        .par_iter()
        .zip(artifacts)
        .enumerate()
        .map(|(index, (tx, artifact))| {
            verify_native_tx_leaf_artifact_record(tx, artifact, None)
                .map_err(|err| reindex_tx_artifact_error(index, err))
        })
        .collect()
}

impl ArtifactVerifier for NativeTxLeafVerifier {
    fn kind(&self) -> ProofArtifactKind {
        ProofArtifactKind::TxLeaf
    }

    fn supports_verifier_profile(&self, verifier_profile: VerifierProfileDigest) -> bool {
        verifier_profile == experimental_native_tx_leaf_verifier_profile()
    }

    fn verify_tx_artifact(
        &self,
        tx: &crate::types::Transaction,
        artifact: &TxValidityArtifact,
    ) -> Result<TxStatementBinding, ProofError> {
        verify_native_tx_leaf_artifact_record(tx, artifact, None).map(|record| record.binding)
    }
}

struct ReceiptRootVerifier;

impl ArtifactVerifier for ReceiptRootVerifier {
    fn kind(&self) -> ProofArtifactKind {
        ProofArtifactKind::ReceiptRoot
    }

    fn supports_verifier_profile(&self, verifier_profile: VerifierProfileDigest) -> bool {
        verifier_profile == experimental_native_receipt_root_verifier_profile()
    }

    fn verify_block_artifact(
        &self,
        txs: &[crate::types::Transaction],
        tx_artifacts: Option<&[TxValidityArtifact]>,
        expected_commitment: &[u8; 48],
        envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError> {
        let max_artifact_bytes = max_native_receipt_root_artifact_bytes(txs.len());
        let tx_artifact_count = tx_artifacts.map(|artifacts| artifacts.len()).unwrap_or(0);
        let artifact_admission_input = ReceiptRootArtifactAdmissionInput {
            envelope_kind: envelope.kind,
            envelope_verifier_profile_matches: envelope.verifier_profile
                == experimental_native_receipt_root_verifier_profile(),
            artifact_bytes_len: envelope.artifact_bytes.len(),
            max_artifact_bytes,
            has_tx_artifacts: tx_artifacts.is_some(),
            tx_artifact_count_matches: tx_artifact_count == txs.len(),
        };
        evaluate_receipt_root_artifact_admission(artifact_admission_input).map_err(
            |rejection| {
                receipt_root_artifact_admission_error(
                    artifact_admission_input,
                    txs.len(),
                    tx_artifact_count,
                    rejection,
                )
            },
        )?;
        let artifacts =
            tx_artifacts.expect("receipt-root artifact admission requires tx artifacts");
        let verified_records = verify_native_tx_leaf_artifact_records(txs, artifacts)?;
        let verified_bindings = verified_records
            .iter()
            .map(|record| record.binding.clone())
            .collect::<Vec<_>>();
        let derived_statement_commitment = commitment_from_statement_bindings(&verified_bindings)?;
        evaluate_receipt_root_statement_binding(ReceiptRootStatementBindingInput {
            statement_commitment_matches: derived_statement_commitment == *expected_commitment,
        })
        .map_err(|_| {
            ProofError::AggregationProofInputsMismatch(
                "receipt-root statement commitment mismatch".to_string(),
            )
        })?;
        let start_verify = Instant::now();
        let leaf_records = verified_records
            .iter()
            .map(|record| record.leaf.clone())
            .collect::<Vec<_>>();
        let verify_mode = load_native_receipt_root_verify_mode();
        let root_metadata = {
            #[cfg(test)]
            if let Some(result) =
                receipt_root_backend_override_result(&leaf_records, artifacts, &envelope.artifact_bytes)
            {
                result
            } else {
                match verify_mode {
                    NativeReceiptRootVerifyMode::Replay => {
                        verify_experimental_native_receipt_root_artifact(
                            artifacts,
                            &envelope.artifact_bytes,
                        )
                    }
                    NativeReceiptRootVerifyMode::VerifiedRecords => {
                        verify_experimental_native_receipt_root_artifact_from_records(
                            &leaf_records,
                            &envelope.artifact_bytes,
                        )
                    }
                    NativeReceiptRootVerifyMode::CrossCheck => {
                        let records_metadata =
                            verify_experimental_native_receipt_root_artifact_from_records(
                                &leaf_records,
                                &envelope.artifact_bytes,
                            )?;
                        let replay_metadata = verify_experimental_native_receipt_root_artifact(
                            artifacts,
                            &envelope.artifact_bytes,
                        )?;
                        if records_metadata != replay_metadata {
                            return Err(ProofError::AggregationProofVerification(
                                "native receipt-root replay and verified-record verification disagreed"
                                    .to_string(),
                            ));
                        }
                        Ok(records_metadata)
                    }
                }
            }
            #[cfg(not(test))]
            {
                match verify_mode {
                    NativeReceiptRootVerifyMode::Replay => {
                        verify_experimental_native_receipt_root_artifact(
                            artifacts,
                            &envelope.artifact_bytes,
                        )
                    }
                    NativeReceiptRootVerifyMode::VerifiedRecords => {
                        verify_experimental_native_receipt_root_artifact_from_records(
                            &leaf_records,
                            &envelope.artifact_bytes,
                        )
                    }
                    NativeReceiptRootVerifyMode::CrossCheck => {
                        let records_metadata =
                            verify_experimental_native_receipt_root_artifact_from_records(
                                &leaf_records,
                                &envelope.artifact_bytes,
                            )?;
                        let replay_metadata = verify_experimental_native_receipt_root_artifact(
                            artifacts,
                            &envelope.artifact_bytes,
                        )?;
                        if records_metadata != replay_metadata {
                            return Err(ProofError::AggregationProofVerification(
                                "native receipt-root replay and verified-record verification disagreed"
                                    .to_string(),
                            ));
                        }
                        Ok(records_metadata)
                    }
                }
            }
        }
        .map_err(|err| {
            ProofError::AggregationProofVerification(format!(
                "native receipt-root verification failed: {err}"
            ))
        })?;
        evaluate_receipt_root_verified_metadata(ReceiptRootVerifiedMetadataInput {
            verified_leaf_count_matches: root_metadata.leaf_count as usize == artifacts.len(),
        })
        .map_err(|_| {
            ProofError::AggregationProofInputsMismatch(
                "receipt-root verified leaf count mismatch".to_string(),
            )
        })?;
        Ok(BlockArtifactVerifyReport {
            tx_count: txs.len(),
            verified_statement_commitment: *expected_commitment,
            verify_ms: start_verify.elapsed().as_millis(),
            verify_batch_ms: 0,
            cache_hit: None,
            cache_build_ms: None,
            root_verify_mode: Some(verify_mode.label()),
        })
    }
}

pub fn recursive_block_artifact_verifier_profile() -> VerifierProfileDigest {
    backend_recursive_block_profile_v2()
}

struct RecursiveBlockVerifier {
    kind: ProofArtifactKind,
}

impl ArtifactVerifier for RecursiveBlockVerifier {
    fn kind(&self) -> ProofArtifactKind {
        self.kind
    }

    fn supports_verifier_profile(&self, verifier_profile: VerifierProfileDigest) -> bool {
        match self.kind {
            ProofArtifactKind::RecursiveBlockV1 => {
                verifier_profile == backend_recursive_block_profile_v1()
            }
            ProofArtifactKind::RecursiveBlockV2 => {
                verifier_profile == backend_recursive_block_profile_v2()
            }
            _ => false,
        }
    }

    fn verify_block_artifact(
        &self,
        _txs: &[crate::types::Transaction],
        _tx_artifacts: Option<&[TxValidityArtifact]>,
        _expected_commitment: &[u8; 48],
        _envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError> {
        Err(ProofError::UnsupportedProofArtifact(format!(
            "recursive block artifacts require verified-record semantic replay; use the product recursive verifier path for {}",
            self.kind.label()
        )))
    }
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

    run_verifier(
        "commitment proof verification".to_string(),
        || verify_block_commitment(proof),
        |err| ProofError::CommitmentProofVerification(err.to_string()),
    )?;
    Ok(())
}

fn panic_payload_to_string(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_string(),
            Err(_) => "non-string panic payload".to_string(),
        },
    }
}

fn run_verifier<T, E, F, M>(context: String, verifier: F, map_err: M) -> Result<T, ProofError>
where
    F: FnOnce() -> Result<T, E>,
    M: FnOnce(E) -> ProofError,
{
    match panic::catch_unwind(AssertUnwindSafe(verifier)) {
        Ok(result) => result.map_err(map_err),
        Err(payload) => Err(ProofError::VerifierPanicked(format!(
            "{context}: {}",
            panic_payload_to_string(payload)
        ))),
    }
}

pub fn tx_validity_receipt_from_proof(
    proof: &TransactionProof,
) -> Result<TxValidityReceipt, String> {
    let statement_hash = checked_transaction_statement_hash_for_receipt(proof)?;
    let public_inputs_digest =
        transaction_public_inputs_digest(proof).map_err(|err| err.to_string())?;
    let verifier_profile =
        transaction_verifier_profile_digest(proof).map_err(|err| err.to_string())?;
    Ok(TxValidityReceipt {
        statement_hash,
        proof_digest: transaction_proof_digest(proof),
        public_inputs_digest,
        verifier_profile,
    })
}

fn checked_transaction_statement_hash_for_receipt(
    proof: &TransactionProof,
) -> Result<[u8; 48], String> {
    transaction_statement_hash_checked(proof).map_err(|err| err.to_string())
}

pub fn tx_validity_artifact_from_proof(
    proof: &TransactionProof,
) -> Result<TxValidityArtifact, ProofError> {
    let receipt = tx_validity_receipt_from_proof(proof)
        .map_err(|message| ProofError::TransactionProofInputsMismatch { index: 0, message })?;
    let artifact_bytes =
        bincode::serialize(proof).map_err(|err| ProofError::TransactionProofVerification {
            index: 0,
            message: format!("failed to serialize inline tx proof artifact: {err}"),
        })?;
    Ok(TxValidityArtifact {
        receipt: receipt.clone(),
        proof: Some(ProofEnvelope {
            kind: ProofArtifactKind::InlineTx,
            verifier_profile: receipt.verifier_profile,
            artifact_bytes,
        }),
    })
}

pub fn tx_validity_artifact_from_tx_leaf_proof(
    proof: &TransactionProof,
) -> Result<TxValidityArtifact, ProofError> {
    let receipt = tx_validity_receipt_from_proof(proof)
        .map_err(|message| ProofError::TransactionProofInputsMismatch { index: 0, message })?;
    let built = build_tx_leaf_artifact_bytes(proof).map_err(|err| {
        ProofError::TransactionProofVerification {
            index: 0,
            message: format!("failed to build tx-leaf artifact: {err}"),
        }
    })?;
    Ok(TxValidityArtifact {
        receipt: receipt.clone(),
        proof: Some(ProofEnvelope {
            kind: ProofArtifactKind::TxLeaf,
            verifier_profile: experimental_tx_leaf_verifier_profile(),
            artifact_bytes: built.artifact_bytes,
        }),
    })
}

pub fn tx_validity_artifact_from_native_tx_leaf_bytes(
    artifact_bytes: Vec<u8>,
) -> Result<TxValidityArtifact, ProofError> {
    let decoded = decode_native_tx_leaf_artifact_bytes(&artifact_bytes).map_err(|err| {
        ProofError::TransactionProofVerification {
            index: 0,
            message: format!("failed to decode native tx-leaf artifact: {err}"),
        }
    })?;
    let receipt = TxValidityReceipt {
        statement_hash: decoded.receipt.statement_hash,
        proof_digest: decoded.receipt.proof_digest,
        public_inputs_digest: decoded.receipt.public_inputs_digest,
        verifier_profile: decoded.receipt.verifier_profile,
    };
    Ok(TxValidityArtifact {
        receipt,
        proof: Some(ProofEnvelope {
            kind: ProofArtifactKind::TxLeaf,
            verifier_profile: experimental_native_tx_leaf_verifier_profile(),
            artifact_bytes,
        }),
    })
}

pub fn tx_validity_artifact_from_receipt(receipt: TxValidityReceipt) -> TxValidityArtifact {
    TxValidityArtifact {
        receipt,
        proof: None,
    }
}

pub fn clear_verified_native_tx_leaf_store() {
    let mut guard = NATIVE_TX_LEAF_VERIFY_CACHE.lock();
    guard.order.clear();
    guard.entries.clear();
}

pub fn prewarm_verified_native_tx_leaf_store(
    transactions: &[crate::types::Transaction],
    artifacts: &[TxValidityArtifact],
) -> Result<(), ProofError> {
    if transactions.len() != artifacts.len() {
        return Err(ProofError::TransactionProofCountMismatch {
            expected: transactions.len(),
            observed: artifacts.len(),
        });
    }
    for (index, (tx, artifact)) in transactions.iter().zip(artifacts).enumerate() {
        verify_native_tx_leaf_artifact_record(tx, artifact, None)
            .map_err(|err| reindex_tx_artifact_error(index, err))?;
    }
    Ok(())
}

fn tx_leaf_public_tx_from_consensus_tx(tx: &crate::types::Transaction) -> TxLeafPublicTx {
    TxLeafPublicTx {
        nullifiers: tx.nullifiers.clone(),
        commitments: tx.commitments.clone(),
        ciphertext_hashes: tx.ciphertext_hashes.clone(),
        balance_tag: tx.balance_tag,
        version: tx.version,
    }
}

fn decode_inline_tx_artifact_proof(
    artifact: &TxValidityArtifact,
) -> Result<TransactionProof, ProofError> {
    let envelope = artifact
        .proof
        .as_ref()
        .ok_or(ProofError::MissingTransactionProofs)?;
    if envelope.kind != ProofArtifactKind::InlineTx {
        return Err(ProofError::UnsupportedProofArtifact(format!(
            "expected inline_tx proof envelope, got {}",
            envelope.kind.label()
        )));
    }
    decode_transaction_proof_bytes_exact(&envelope.artifact_bytes).map_err(|err| {
        ProofError::TransactionProofVerification {
            index: 0,
            message: format!("failed to decode inline tx proof artifact: {err}"),
        }
    })
}

fn decode_signed_magnitude(sign: u8, magnitude: u64, label: &str) -> Result<i128, String> {
    match sign {
        0 => Ok(i128::from(magnitude)),
        1 => Ok(-i128::from(magnitude)),
        other => Err(format!("{label} sign flag must be 0 or 1, got {other}")),
    }
}

fn statement_hash_from_tx_and_stark_inputs(
    tx: &crate::types::Transaction,
    stark_inputs: &SerializedStarkInputs,
) -> Result<[u8; 48], String> {
    let value_balance = decode_signed_magnitude(
        stark_inputs.value_balance_sign,
        stark_inputs.value_balance_magnitude,
        "value_balance",
    )?;
    let stablecoin_issuance = decode_signed_magnitude(
        stark_inputs.stablecoin_issuance_sign,
        stark_inputs.stablecoin_issuance_magnitude,
        "stablecoin_issuance",
    )?;

    transaction_statement_hash_from_parts(
        &stark_inputs.merkle_root,
        &tx.nullifiers,
        &tx.commitments,
        &tx.ciphertext_hashes,
        stark_inputs.fee,
        value_balance,
        &tx.balance_tag,
        tx.version.circuit,
        tx.version.crypto,
        stark_inputs.stablecoin_enabled,
        stark_inputs.stablecoin_asset_id,
        &stark_inputs.stablecoin_policy_hash,
        &stark_inputs.stablecoin_oracle_commitment,
        &stark_inputs.stablecoin_attestation_commitment,
        stablecoin_issuance,
        stark_inputs.stablecoin_policy_version,
    )
    .map_err(|err| err.to_string())
}

fn statement_binding_from_tx_leaf(
    tx: &crate::types::Transaction,
    receipt: &TxValidityReceipt,
    stark_inputs: &SerializedStarkInputs,
) -> Result<TxStatementBinding, String> {
    let expected_statement_hash = statement_hash_from_tx_and_stark_inputs(tx, stark_inputs)?;
    if expected_statement_hash != receipt.statement_hash {
        return Err("tx-leaf statement hash mismatch".to_string());
    }
    let expected_public_inputs_digest =
        transaction_public_inputs_digest_from_serialized(stark_inputs)
            .map_err(|err| format!("failed to hash tx-leaf STARK public inputs: {err}"))?;
    if expected_public_inputs_digest != receipt.public_inputs_digest {
        return Err("tx-leaf public inputs digest mismatch".to_string());
    }
    Ok(TxStatementBinding {
        statement_hash: receipt.statement_hash,
        anchor: stark_inputs.merkle_root,
        fee: stark_inputs.fee,
        circuit_version: u32::from(tx.version.circuit),
    })
}

fn verify_transaction_proof_inputs_unindexed(
    tx: &crate::types::Transaction,
    proof: &TransactionProof,
) -> Result<(), String> {
    if proof.version_binding() != tx.version {
        return Err("version binding mismatch".to_string());
    }

    let expected_nullifiers: Vec<[u8; 48]> = proof
        .nullifiers
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 48])
        .collect();
    if tx.nullifiers != expected_nullifiers {
        return Err("nullifier list mismatch".to_string());
    }

    let expected_commitments: Vec<[u8; 48]> = proof
        .commitments
        .iter()
        .copied()
        .filter(|value| *value != [0u8; 48])
        .collect();
    if tx.commitments != expected_commitments {
        return Err("commitment list mismatch".to_string());
    }

    if tx.balance_tag != proof.public_inputs.balance_tag {
        return Err("balance tag mismatch".to_string());
    }

    if !tx.ciphertexts.is_empty() {
        let mut derived_hashes: Vec<[u8; 48]> = tx
            .ciphertexts
            .iter()
            .map(|ciphertext| ciphertext_hash_bytes(ciphertext))
            .collect();
        derived_hashes.resize(MAX_OUTPUTS, [0u8; 48]);
        if derived_hashes != proof.public_inputs.ciphertext_hashes {
            return Err("ciphertext hash mismatch".to_string());
        }
    }

    let mut expected_ciphertext_hashes = tx.ciphertext_hashes.clone();
    expected_ciphertext_hashes.resize(MAX_OUTPUTS, [0u8; 48]);
    if expected_ciphertext_hashes != proof.public_inputs.ciphertext_hashes {
        return Err("ciphertext hash mismatch".to_string());
    }

    Ok(())
}

fn verify_transaction_proof_unindexed(
    verifying_key: &transaction_circuit::keys::VerifyingKey,
    proof: &TransactionProof,
) -> Result<(), String> {
    verify_transaction_proof(proof, verifying_key)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

fn reindex_tx_artifact_error(index: usize, error: ProofError) -> ProofError {
    match error {
        ProofError::TransactionProofInputsMismatch { message, .. } => {
            ProofError::TransactionProofInputsMismatch { index, message }
        }
        ProofError::TransactionProofVerification { message, .. } => {
            ProofError::TransactionProofVerification { index, message }
        }
        other => other,
    }
}

fn verify_tx_validity_artifacts(
    registry: &VerifierRegistry,
    transactions: &[crate::types::Transaction],
    artifacts: &[TxValidityArtifact],
) -> Result<Vec<TxValidityClaim>, ProofError> {
    if artifacts.len() != transactions.len() {
        return Err(ProofError::TransactionProofCountMismatch {
            expected: transactions.len(),
            observed: artifacts.len(),
        });
    }

    transactions
        .par_iter()
        .zip(artifacts)
        .enumerate()
        .map(|(index, (tx, artifact))| {
            let envelope = artifact
                .proof
                .as_ref()
                .ok_or(ProofError::MissingTransactionProofs)?;
            let verifier = registry.resolve(envelope.kind, envelope.verifier_profile)?;
            verifier
                .verify_tx_artifact(tx, artifact)
                .map(|binding| TxValidityClaim::new(artifact.receipt.clone(), binding))
                .map_err(|err| reindex_tx_artifact_error(index, err))
        })
        .collect()
}

pub fn tx_validity_claims_from_tx_artifacts(
    transactions: &[crate::types::Transaction],
    artifacts: &[TxValidityArtifact],
) -> Result<Vec<TxValidityClaim>, ProofError> {
    verify_tx_validity_artifacts(&VerifierRegistry::default(), transactions, artifacts)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TxValidityClaimMatchRejection {
    Count,
    ReceiptStatementHash,
    ReceiptProofDigest,
    ReceiptPublicInputsDigest,
    ReceiptVerifierProfile,
    BindingStatementHash,
    BindingAnchorRoot,
    BindingFee,
    BindingCircuitVersion,
}

impl TxValidityClaimMatchRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::Count => "count_mismatch",
            Self::ReceiptStatementHash => "receipt_statement_hash_mismatch",
            Self::ReceiptProofDigest => "receipt_proof_digest_mismatch",
            Self::ReceiptPublicInputsDigest => "receipt_public_inputs_digest_mismatch",
            Self::ReceiptVerifierProfile => "receipt_verifier_profile_mismatch",
            Self::BindingStatementHash => "binding_statement_hash_mismatch",
            Self::BindingAnchorRoot => "binding_anchor_root_mismatch",
            Self::BindingFee => "binding_fee_mismatch",
            Self::BindingCircuitVersion => "binding_circuit_version_mismatch",
        }
    }
}

fn evaluate_tx_validity_claim_match(
    provided: &TxValidityClaim,
    verified: &TxValidityClaim,
) -> Result<(), TxValidityClaimMatchRejection> {
    if provided.receipt.statement_hash != verified.receipt.statement_hash {
        return Err(TxValidityClaimMatchRejection::ReceiptStatementHash);
    }
    if provided.receipt.proof_digest != verified.receipt.proof_digest {
        return Err(TxValidityClaimMatchRejection::ReceiptProofDigest);
    }
    if provided.receipt.public_inputs_digest != verified.receipt.public_inputs_digest {
        return Err(TxValidityClaimMatchRejection::ReceiptPublicInputsDigest);
    }
    if provided.receipt.verifier_profile != verified.receipt.verifier_profile {
        return Err(TxValidityClaimMatchRejection::ReceiptVerifierProfile);
    }
    if provided.binding.statement_hash != verified.binding.statement_hash {
        return Err(TxValidityClaimMatchRejection::BindingStatementHash);
    }
    if provided.binding.anchor != verified.binding.anchor {
        return Err(TxValidityClaimMatchRejection::BindingAnchorRoot);
    }
    if provided.binding.fee != verified.binding.fee {
        return Err(TxValidityClaimMatchRejection::BindingFee);
    }
    if provided.binding.circuit_version != verified.binding.circuit_version {
        return Err(TxValidityClaimMatchRejection::BindingCircuitVersion);
    }
    Ok(())
}

fn evaluate_tx_validity_claims_match_verified_artifacts(
    provided_claims: &[TxValidityClaim],
    verified_claims: &[TxValidityClaim],
) -> Result<(), TxValidityClaimMatchRejection> {
    if provided_claims.len() != verified_claims.len() {
        return Err(TxValidityClaimMatchRejection::Count);
    }
    provided_claims
        .iter()
        .zip(verified_claims)
        .try_for_each(|(provided, verified)| evaluate_tx_validity_claim_match(provided, verified))
}

fn ensure_claims_match_verified_artifacts(
    provided_claims: &[TxValidityClaim],
    verified_claims: &[TxValidityClaim],
) -> Result<(), ProofError> {
    evaluate_tx_validity_claims_match_verified_artifacts(provided_claims, verified_claims).map_err(
        |_| {
            ProofError::AggregationProofInputsMismatch(
                "provided tx validity claims do not match verified backend artifacts".to_string(),
            )
        },
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProvenBatchBindingInput {
    proven_batch_mode: ProvenBatchMode,
    proof_kind: ProofArtifactKind,
    tx_count: usize,
    expected_tx_count: usize,
    statement_commitment_matches: bool,
    da_root_matches: bool,
    da_chunk_count: u32,
    expected_da_chunk_count: u32,
    artifact_kind: Option<ProofArtifactKind>,
    artifact_verifier_profile_matches: bool,
    has_receipt_root: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProvenBatchBindingRejection {
    IncompatibleRoute,
    TxCountMismatch,
    StatementCommitmentMismatch,
    DaRootMismatch,
    DaChunkCountZero,
    DaChunkCountMismatch,
    MissingRecursiveBlockArtifact,
    ArtifactKindMismatch,
    ArtifactVerifierProfileMismatch,
    RecursiveBlockReceiptRootPayload,
}

impl ProvenBatchBindingRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::IncompatibleRoute => "incompatible_route",
            Self::TxCountMismatch => "tx_count_mismatch",
            Self::StatementCommitmentMismatch => "statement_commitment_mismatch",
            Self::DaRootMismatch => "da_root_mismatch",
            Self::DaChunkCountZero => "da_chunk_count_zero",
            Self::DaChunkCountMismatch => "da_chunk_count_mismatch",
            Self::MissingRecursiveBlockArtifact => "missing_recursive_block_artifact",
            Self::ArtifactKindMismatch => "artifact_kind_mismatch",
            Self::ArtifactVerifierProfileMismatch => "artifact_verifier_profile_mismatch",
            Self::RecursiveBlockReceiptRootPayload => "recursive_block_receipt_root_payload",
        }
    }
}

fn evaluate_proven_batch_binding(
    input: ProvenBatchBindingInput,
) -> Result<(), ProvenBatchBindingRejection> {
    if !crate::types::ArtifactRoute::new(input.proven_batch_mode, input.proof_kind)
        .is_compatible_with_mode()
    {
        return Err(ProvenBatchBindingRejection::IncompatibleRoute);
    }
    if input.tx_count != input.expected_tx_count {
        return Err(ProvenBatchBindingRejection::TxCountMismatch);
    }
    if !input.statement_commitment_matches {
        return Err(ProvenBatchBindingRejection::StatementCommitmentMismatch);
    }
    if !input.da_root_matches {
        return Err(ProvenBatchBindingRejection::DaRootMismatch);
    }
    if input.da_chunk_count == 0 {
        return Err(ProvenBatchBindingRejection::DaChunkCountZero);
    }
    if input.da_chunk_count != input.expected_da_chunk_count {
        return Err(ProvenBatchBindingRejection::DaChunkCountMismatch);
    }
    if matches!(input.proven_batch_mode, ProvenBatchMode::RecursiveBlock)
        && input.artifact_kind.is_none()
    {
        return Err(ProvenBatchBindingRejection::MissingRecursiveBlockArtifact);
    }
    if let Some(artifact_kind) = input.artifact_kind {
        if artifact_kind != input.proof_kind {
            return Err(ProvenBatchBindingRejection::ArtifactKindMismatch);
        }
        if !input.artifact_verifier_profile_matches {
            return Err(ProvenBatchBindingRejection::ArtifactVerifierProfileMismatch);
        }
    }
    if matches!(input.proven_batch_mode, ProvenBatchMode::RecursiveBlock) && input.has_receipt_root
    {
        return Err(ProvenBatchBindingRejection::RecursiveBlockReceiptRootPayload);
    }
    Ok(())
}

fn validate_proven_batch_binding<BH>(
    block: &Block<BH>,
    proven_batch: &crate::types::ProvenBatch,
    expected_commitment: &[u8; 48],
    block_artifact: Option<&ProofEnvelope>,
) -> Result<(), ProofError>
where
    BH: HeaderProofExt,
{
    let expected_da_encoding =
        crate::types::encode_da_blob(&block.transactions, block.header.da_params())
            .map_err(|err| ProofError::DaEncoding(err.to_string()))?;
    let expected_da_root = expected_da_encoding.root();
    let expected_da_chunk_count = u32::try_from(expected_da_encoding.chunks().len())
        .map_err(|_| ProofError::DaEncoding("DA chunk count exceeds u32".to_string()))?;
    let artifact_kind = block_artifact.map(|artifact| artifact.kind);
    let artifact_verifier_profile_matches = block_artifact
        .map(|artifact| artifact.verifier_profile == proven_batch.verifier_profile)
        .unwrap_or(true);
    let input = ProvenBatchBindingInput {
        proven_batch_mode: proven_batch.mode,
        proof_kind: proven_batch.proof_kind,
        tx_count: proven_batch.tx_count as usize,
        expected_tx_count: block.transactions.len(),
        statement_commitment_matches: proven_batch.tx_statements_commitment == *expected_commitment,
        da_root_matches: proven_batch.da_root == expected_da_root,
        da_chunk_count: proven_batch.da_chunk_count,
        expected_da_chunk_count,
        artifact_kind,
        artifact_verifier_profile_matches,
        has_receipt_root: proven_batch.receipt_root.is_some(),
    };
    evaluate_proven_batch_binding(input).map_err(|rejection| match rejection {
        ProvenBatchBindingRejection::IncompatibleRoute => {
            ProofError::ProvenBatchBindingMismatch(format!(
                "proven batch route mode={:?} kind={} is incompatible",
                proven_batch.mode,
                proven_batch.proof_kind.label()
            ))
        }
        ProvenBatchBindingRejection::TxCountMismatch => {
            ProofError::ProvenBatchBindingMismatch(format!(
                "proven batch tx_count mismatch (payload {}, expected {})",
                proven_batch.tx_count,
                block.transactions.len()
            ))
        }
        ProvenBatchBindingRejection::StatementCommitmentMismatch => {
            ProofError::ProvenBatchBindingMismatch(
                "proven batch statement commitment mismatch".to_string(),
            )
        }
        ProvenBatchBindingRejection::DaRootMismatch => {
            ProofError::ProvenBatchBindingMismatch("proven batch DA root mismatch".to_string())
        }
        ProvenBatchBindingRejection::DaChunkCountZero => ProofError::ProvenBatchBindingMismatch(
            "proven batch DA chunk count must be non-zero".to_string(),
        ),
        ProvenBatchBindingRejection::DaChunkCountMismatch => {
            ProofError::ProvenBatchBindingMismatch(format!(
                "proven batch DA chunk count mismatch (payload {}, expected {})",
                proven_batch.da_chunk_count, expected_da_chunk_count
            ))
        }
        ProvenBatchBindingRejection::MissingRecursiveBlockArtifact => {
            ProofError::ProvenBatchBindingMismatch(
                "recursive block proven batch requires block artifact".to_string(),
            )
        }
        ProvenBatchBindingRejection::ArtifactKindMismatch => {
            let envelope = block_artifact.expect("artifact kind mismatch requires artifact");
            ProofError::ProvenBatchBindingMismatch(format!(
                "block artifact kind {} does not match proven batch kind {}",
                envelope.kind.label(),
                proven_batch.proof_kind.label()
            ))
        }
        ProvenBatchBindingRejection::ArtifactVerifierProfileMismatch => {
            ProofError::ProvenBatchBindingMismatch(
                "block artifact verifier profile does not match proven batch".to_string(),
            )
        }
        ProvenBatchBindingRejection::RecursiveBlockReceiptRootPayload => {
            ProofError::ProvenBatchBindingMismatch(
                "recursive block proven batch must not carry receipt_root payload".to_string(),
            )
        }
    })
}

pub fn tx_statement_bindings_from_tx_artifacts(
    transactions: &[crate::types::Transaction],
    artifacts: &[TxValidityArtifact],
) -> Result<Vec<TxStatementBinding>, ProofError> {
    tx_statement_bindings_from_claims(&tx_validity_claims_from_tx_artifacts(
        transactions,
        artifacts,
    )?)
}

#[derive(Clone, Debug, Default)]
pub struct HashVerifier;

impl ProofVerifier for HashVerifier {
    fn verify_block_with_backend<BH>(
        &self,
        block: &Block<BH>,
        _backend_inputs: Option<&BlockBackendInputs>,
        parent_commitment_tree: &CommitmentTreeState,
    ) -> Result<CommitmentTreeState, ProofError>
    where
        BH: HeaderProofExt,
    {
        verify_commitments(block)?;
        apply_commitments(parent_commitment_tree, &block.transactions)
    }
}

#[derive(Clone)]
pub struct ParallelProofVerifier {
    verifier_registry: VerifierRegistry,
}

impl ParallelProofVerifier {
    pub fn new() -> Self {
        let _ = generate_keys();
        Self {
            verifier_registry: VerifierRegistry::default(),
        }
    }
}

impl Default for ParallelProofVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ProofVerifier for ParallelProofVerifier {
    fn verify_block_with_backend<BH>(
        &self,
        block: &Block<BH>,
        backend_inputs: Option<&BlockBackendInputs>,
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
        let ciphertext_bytes_total: usize = block
            .transactions
            .iter()
            .flat_map(|tx| tx.ciphertexts.iter())
            .map(|ct| ct.len())
            .sum();
        let verification_mode = block.proof_verification_mode;
        let tx_validity_artifacts =
            backend_inputs.and_then(BlockBackendInputs::tx_validity_artifacts);
        let policy_input = BlockProofPolicyInput {
            tx_count,
            verification_mode,
            has_proven_batch: block.proven_batch.is_some(),
            proven_batch_mode: block
                .proven_batch
                .as_ref()
                .map(|batch| batch.mode)
                .unwrap_or(ProvenBatchMode::RecursiveBlock),
            commitment_proof_bytes,
            has_block_artifact: block.block_artifact.is_some(),
            has_receipt_root: block
                .proven_batch
                .as_ref()
                .and_then(|batch| batch.receipt_root.as_ref())
                .is_some(),
            has_tx_validity_artifacts: tx_validity_artifacts.is_some(),
            tx_validity_artifact_count: tx_validity_artifacts
                .map(|artifacts| artifacts.len())
                .unwrap_or(0),
            has_tx_validity_claims: block.tx_validity_claims.is_some(),
        };
        if let Err(rejection) = evaluate_block_proof_policy(policy_input) {
            return Err(proof_policy_rejection_to_error(rejection, policy_input));
        }

        if block.transactions.is_empty() {
            return apply_commitments(parent_commitment_tree, &block.transactions);
        }

        let tx_proof_bytes_total: usize = tx_validity_artifacts
            .map(|artifacts| {
                artifacts
                    .iter()
                    .filter_map(|artifact| artifact.proof.as_ref())
                    .map(|envelope| envelope.artifact_bytes.len())
                    .sum()
            })
            .unwrap_or(0);

        if let Some(artifacts) = tx_validity_artifacts
            && artifacts.len() != block.transactions.len()
        {
            return Err(ProofError::TransactionProofCountMismatch {
                expected: block.transactions.len(),
                observed: artifacts.len(),
            });
        }
        if tx_validity_artifacts.is_none() {
            return Err(ProofError::MissingTransactionProofs);
        }
        let derived_claims_from_artifacts = tx_validity_artifacts
            .map(|artifacts| tx_validity_claims_from_tx_artifacts(&block.transactions, artifacts))
            .transpose()?;

        let resolved_claims = if let Some(claims) = block.tx_validity_claims.clone() {
            if claims.len() != block.transactions.len() {
                return Err(ProofError::CommitmentProofInputsMismatch(format!(
                    "transaction claim count mismatch (expected {}, got {})",
                    block.transactions.len(),
                    claims.len()
                )));
            }
            if let Some(derived_claims) = derived_claims_from_artifacts.as_ref() {
                ensure_claims_match_verified_artifacts(&claims, derived_claims)?;
            }
            Some(derived_claims_from_artifacts.clone().unwrap_or(claims))
        } else {
            None
        };
        if !matches!(
            verification_mode,
            ProofVerificationMode::SelfContainedAggregation
        ) {
            return Err(ProofError::UnsupportedProofArtifact(
                "legacy InlineRequired block verification is no longer supported on the product path"
                    .to_string(),
            ));
        }

        let proven_batch = block
            .proven_batch
            .as_ref()
            .ok_or(ProofError::MissingProvenBatchForSelfContained)?;
        let commitment_proof = &proven_batch.commitment_proof;

        let commitment_verify_ms = if matches!(proven_batch.mode, ProvenBatchMode::ReceiptRoot) {
            let start_commitment = Instant::now();
            verify_commitment_proof_payload(block, parent_commitment_tree, commitment_proof)?;
            start_commitment.elapsed().as_millis()
        } else {
            if !commitment_proof.proof_bytes.is_empty() {
                return Err(ProofError::UnsupportedProofArtifact(
                    "recursive block product lane forbids commitment proof bytes".to_string(),
                ));
            }
            0
        };

        if matches!(
            verification_mode,
            ProofVerificationMode::SelfContainedAggregation
        ) && resolved_claims.is_none()
        {
            return Err(ProofError::MissingTransactionValidityClaims);
        }

        let resolved_statement_bindings = resolved_claims
            .as_deref()
            .map(tx_statement_bindings_from_claims)
            .transpose()?;
        let statement_bindings = resolved_statement_bindings
            .as_deref()
            .ok_or(ProofError::MissingTransactionValidityClaims)?;
        validate_statement_anchor_history(
            parent_commitment_tree,
            block.transactions.len(),
            statement_bindings,
        )?;
        let resolved_receipts = resolved_claims
            .as_deref()
            .map(tx_validity_receipts_from_claims);
        let derived_statement_commitment =
            Some(commitment_from_statement_bindings(statement_bindings)?);
        let expected_commitment =
            match (block.tx_statements_commitment, derived_statement_commitment) {
                (Some(expected), Some(derived)) => {
                    if expected != derived {
                        return Err(ProofError::CommitmentProofInputsMismatch(
                            "tx_statements_commitment does not match provided transaction claims"
                                .to_string(),
                        ));
                    }
                    expected
                }
                (Some(expected), None) => expected,
                (None, Some(derived)) => derived,
                (None, None) => {
                    return Err(ProofError::MissingTransactionValidityClaims);
                }
            };
        if matches!(proven_batch.mode, ProvenBatchMode::ReceiptRoot) {
            let proof_commitment =
                felts_to_bytes48(&commitment_proof.public_inputs.tx_statements_commitment);
            if expected_commitment != proof_commitment {
                return Err(ProofError::CommitmentProofInputsMismatch(
                    "tx_statements_commitment mismatch".to_string(),
                ));
            }
        }

        let block_artifact = block
            .block_artifact
            .clone()
            .or_else(|| match proven_batch.mode {
                ProvenBatchMode::ReceiptRoot => {
                    proven_batch
                        .receipt_root
                        .as_ref()
                        .map(|receipt_root| ProofEnvelope {
                            kind: proven_batch.proof_kind,
                            verifier_profile: proven_batch.verifier_profile,
                            artifact_bytes: receipt_root.root_proof.clone(),
                        })
                }
                ProvenBatchMode::RecursiveBlock => None,
                ProvenBatchMode::InlineTx => None,
            });
        validate_proven_batch_binding(
            block,
            proven_batch,
            &expected_commitment,
            block_artifact.as_ref(),
        )?;

        let aggregation_proof_bytes =
            total_batch_proof_payload_bytes(proven_batch, block_artifact.as_ref());
        let aggregation_proof_uncompressed_bytes =
            total_batch_proof_uncompressed_bytes(proven_batch, block_artifact.as_ref());
        let tx_verify_ms = 0u128;
        let aggregation_cache_hit = false;
        let aggregation_cache_build_ms = 0u128;
        let aggregation_cache_prewarm_hit = false;
        let aggregation_cache_prewarm_build_ms = 0u128;
        let aggregation_cache_prewarm_total_ms = 0u128;

        let recursive_semantic = if matches!(proven_batch.mode, ProvenBatchMode::RecursiveBlock) {
            Some(recursive_block_semantic_inputs_from_block(
                block,
                parent_commitment_tree,
                expected_commitment,
            )?)
        } else {
            None
        };

        let (
            aggregation_verified,
            aggregation_verify_ms,
            aggregation_verify_batch_ms,
            aggregation_verify_mode,
        ) = match proven_batch.mode {
            ProvenBatchMode::InlineTx => {
                return Err(ProofError::UnsupportedProofArtifact(
                    "legacy InlineTx proven batches are no longer supported on the product path"
                        .to_string(),
                ));
            }
            ProvenBatchMode::ReceiptRoot => {
                let receipt_root = proven_batch.receipt_root.as_ref().ok_or_else(|| {
                    ProofError::ProvenBatchBindingMismatch(
                        "missing receipt_root payload for ReceiptRoot mode".to_string(),
                    )
                })?;
                let claim_receipts = resolved_receipts.as_ref();
                let payload_admission_input = ReceiptRootPayloadAdmissionInput {
                    payload_leaf_count_matches: receipt_root.metadata.leaf_count == tx_count as u32,
                    payload_receipt_count_matches: receipt_root.receipts.len() == tx_count,
                    has_claim_receipts: claim_receipts.is_some(),
                    payload_receipts_match_claims: claim_receipts
                        .map(|claims| receipt_root.receipts == *claims)
                        .unwrap_or(false),
                    has_tx_artifacts: tx_validity_artifacts.is_some(),
                };
                evaluate_receipt_root_payload_admission(payload_admission_input).map_err(
                    |rejection| match rejection {
                        ReceiptRootPayloadAdmissionRejection::LeafCountMismatch => {
                            ProofError::ProvenBatchBindingMismatch(format!(
                                "receipt-root leaf_count mismatch (payload {}, expected {})",
                                receipt_root.metadata.leaf_count, tx_count
                            ))
                        }
                        ReceiptRootPayloadAdmissionRejection::ReceiptCountMismatch => {
                            ProofError::ProvenBatchBindingMismatch(format!(
                                "receipt-root receipt count mismatch (payload {}, expected {})",
                                receipt_root.receipts.len(),
                                tx_count
                            ))
                        }
                        ReceiptRootPayloadAdmissionRejection::MissingClaimReceipts => {
                            ProofError::MissingTransactionValidityClaims
                        }
                        ReceiptRootPayloadAdmissionRejection::ReceiptsMismatch => {
                            ProofError::ProvenBatchBindingMismatch(
                                "receipt-root payload receipts do not match tx validity claims"
                                    .to_string(),
                            )
                        }
                        ReceiptRootPayloadAdmissionRejection::MissingTransactionProofs => {
                            ProofError::MissingTransactionProofs
                        }
                    },
                )?;
                let artifacts = tx_validity_artifacts
                    .expect("receipt-root payload admission requires tx artifacts");
                let receipt_root_verifier = self
                    .verifier_registry
                    .resolve(proven_batch.proof_kind, proven_batch.verifier_profile)?;
                let verify_report = receipt_root_verifier.verify_block_artifact(
                    &block.transactions,
                    Some(artifacts),
                    &expected_commitment,
                    block_artifact
                        .as_ref()
                        .ok_or(ProofError::MissingAggregationProofForSelfContainedMode)?,
                )?;
                (
                    true,
                    verify_report.verify_ms,
                    verify_report.verify_batch_ms,
                    verify_report.root_verify_mode.unwrap_or("unknown"),
                )
            }
            ProvenBatchMode::RecursiveBlock => {
                let artifacts =
                    tx_validity_artifacts.ok_or(ProofError::MissingTransactionProofs)?;
                let recursive_artifact = block_artifact
                    .as_ref()
                    .ok_or(ProofError::MissingAggregationProofForSelfContainedMode)?;
                let verify_report = verify_recursive_block_artifact_against_verified_records(
                    &block.transactions,
                    artifacts,
                    &expected_commitment,
                    recursive_semantic
                        .as_ref()
                        .ok_or(ProofError::MissingAggregationProofForSelfContainedMode)?,
                    recursive_artifact,
                )?;
                (
                    true,
                    verify_report.verify_ms,
                    verify_report.verify_batch_ms,
                    verify_report.root_verify_mode.unwrap_or("unknown"),
                )
            }
        };

        let (proof_starting_root, proof_ending_root) = match proven_batch.mode {
            ProvenBatchMode::ReceiptRoot => (
                felts_to_bytes48(&commitment_proof.public_inputs.starting_state_root),
                felts_to_bytes48(&commitment_proof.public_inputs.ending_state_root),
            ),
            ProvenBatchMode::RecursiveBlock => {
                let recursive_semantic = recursive_semantic
                    .as_ref()
                    .ok_or(ProofError::MissingAggregationProofForSelfContainedMode)?;
                (
                    recursive_semantic.start_shielded_root,
                    recursive_semantic.end_shielded_root,
                )
            }
            ProvenBatchMode::InlineTx => unreachable!("InlineTx already rejected"),
        };
        let result = verify_and_apply_tree_transition_without_anchors(
            parent_commitment_tree,
            proof_starting_root,
            proof_ending_root,
            &block.transactions,
        )?;

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
            aggregation_verify_mode,
            aggregation_cache_hit,
            aggregation_cache_build_ms,
            aggregation_cache_prewarm_hit,
            aggregation_cache_prewarm_build_ms,
            aggregation_cache_prewarm_total_ms,
            tx_verify_ms,
            total_verify_ms = start_total.elapsed().as_millis(),
            aggregation_verified,
            "block_proof_verification_metrics"
        );

        Ok(result)
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

fn validate_statement_anchor_history(
    parent_commitment_tree: &CommitmentTreeState,
    tx_count: usize,
    bindings: &[TxStatementBinding],
) -> Result<(), ProofError> {
    if bindings.len() != tx_count {
        return Err(ProofError::CommitmentProofInputsMismatch(format!(
            "statement binding count mismatch (expected {}, got {})",
            tx_count,
            bindings.len()
        )));
    }

    for (index, binding) in bindings.iter().enumerate() {
        if !parent_commitment_tree.contains_root(&binding.anchor) {
            return Err(ProofError::InvalidAnchor {
                index,
                anchor: binding.anchor,
            });
        }
    }

    Ok(())
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

fn commitment_from_receipts(receipts: &[TxValidityReceipt]) -> Result<[u8; 48], ProofError> {
    let hashes = receipts
        .iter()
        .map(|receipt| receipt.statement_hash)
        .collect::<Vec<_>>();
    CommitmentBlockProver::commitment_from_statement_hashes(&hashes)
        .map_err(|err| ProofError::AggregationProofInputsMismatch(err.to_string()))
}

pub fn receipt_statement_commitment(
    receipts: &[TxValidityReceipt],
) -> Result<[u8; 48], ProofError> {
    commitment_from_receipts(receipts)
}

pub fn claim_statement_commitment(claims: &[TxValidityClaim]) -> Result<[u8; 48], ProofError> {
    let bindings = tx_statement_bindings_from_claims(claims)?;
    commitment_from_statement_bindings(&bindings)
}

fn total_batch_proof_payload_bytes(
    batch: &crate::types::ProvenBatch,
    block_artifact: Option<&ProofEnvelope>,
) -> usize {
    match batch.mode {
        ProvenBatchMode::InlineTx => 0,
        ProvenBatchMode::ReceiptRoot => batch
            .receipt_root
            .as_ref()
            .map(|receipt_root| receipt_root.root_proof.len())
            .unwrap_or(0),
        ProvenBatchMode::RecursiveBlock => block_artifact
            .map(|artifact| artifact.artifact_bytes.len())
            .unwrap_or(0),
    }
}

fn total_batch_proof_uncompressed_bytes(
    batch: &crate::types::ProvenBatch,
    block_artifact: Option<&ProofEnvelope>,
) -> usize {
    match batch.mode {
        ProvenBatchMode::InlineTx => 0,
        ProvenBatchMode::ReceiptRoot => batch
            .receipt_root
            .as_ref()
            .map(|receipt_root| receipt_root.root_proof.len())
            .unwrap_or(0),
        ProvenBatchMode::RecursiveBlock => block_artifact
            .map(|artifact| artifact.artifact_bytes.len())
            .unwrap_or(0),
    }
}

fn statement_hash_from_proof(proof: &transaction_circuit::TransactionProof) -> [u8; 48] {
    transaction_statement_hash(proof)
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

#[cfg(test)]
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
    use protocol_versioning::VersionBinding;
    use serde::Deserialize;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex, OnceLock};

    static TEST_ENV_LOCK: StdMutex<()> = StdMutex::new(());

    struct EnvGuard {
        previous_verify_mode: Option<String>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanProofPolicyVectorFile {
        schema_version: u32,
        proof_policy_cases: Vec<LeanProofPolicyCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanProofPolicyCase {
        name: String,
        tx_count: usize,
        verification_mode: String,
        has_proven_batch: bool,
        batch_mode: String,
        commitment_proof_bytes: usize,
        has_block_artifact: bool,
        has_receipt_root: bool,
        has_tx_validity_artifacts: bool,
        tx_validity_artifact_count: usize,
        has_tx_validity_claims: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNativeTxLeafAdmissionVectorFile {
        schema_version: u32,
        native_tx_leaf_admission_cases: Vec<LeanNativeTxLeafAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanNativeTxLeafAdmissionCase {
        name: String,
        has_envelope: bool,
        envelope_kind: String,
        envelope_verifier_profile_matches: bool,
        artifact_bytes_len: usize,
        max_artifact_bytes: usize,
        receipt_verifier_profile_matches: bool,
        has_expected_artifact_hash: bool,
        expected_artifact_hash_matches: bool,
        has_cache_entry: bool,
        cache_receipt_matches: bool,
        cache_transaction_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
        expected_outcome: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTxValidityClaimMatchVectorFile {
        schema_version: u32,
        tx_validity_claim_match_cases: Vec<LeanTxValidityClaimMatchCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTxValidityClaimMatchCase {
        name: String,
        count_matches: bool,
        receipt_statement_hash_matches: bool,
        receipt_proof_digest_matches: bool,
        receipt_public_inputs_digest_matches: bool,
        receipt_verifier_profile_matches: bool,
        binding_statement_hash_matches: bool,
        binding_anchor_root_matches: bool,
        binding_fee_matches: bool,
        binding_circuit_version_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanReceiptRootAdmissionVectorFile {
        schema_version: u32,
        payload_cases: Vec<LeanReceiptRootPayloadCase>,
        artifact_cases: Vec<LeanReceiptRootArtifactCase>,
        statement_cases: Vec<LeanReceiptRootStatementCase>,
        verified_metadata_cases: Vec<LeanReceiptRootVerifiedMetadataCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanReceiptRootPayloadCase {
        name: String,
        payload_leaf_count_matches: bool,
        payload_receipt_count_matches: bool,
        has_claim_receipts: bool,
        payload_receipts_match_claims: bool,
        has_tx_artifacts: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanReceiptRootArtifactCase {
        name: String,
        envelope_kind: String,
        envelope_verifier_profile_matches: bool,
        artifact_bytes_len: usize,
        max_artifact_bytes: usize,
        has_tx_artifacts: bool,
        tx_artifact_count_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanReceiptRootStatementCase {
        name: String,
        statement_commitment_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanReceiptRootVerifiedMetadataCase {
        name: String,
        verified_leaf_count_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRecursiveBlockAdmissionVectorFile {
        schema_version: u32,
        artifact_cases: Vec<LeanRecursiveBlockArtifactCase>,
        direct_verifier_cases: Vec<LeanRecursiveBlockDirectVerifierCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRecursiveBlockArtifactCase {
        name: String,
        expected_kind: String,
        envelope_kind: String,
        verifier_profile_matches: bool,
        artifact_bytes_len: usize,
        max_artifact_bytes: usize,
        artifact_decoded: bool,
        header_version_matches: bool,
        tx_count_matches: bool,
        statement_commitment_matches: bool,
        public_replay_matches: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRecursiveBlockDirectVerifierCase {
        name: String,
        kind: String,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRecursiveSemanticInputVectorFile {
        schema_version: u32,
        semantic_cases: Vec<LeanRecursiveSemanticInputCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanRecursiveSemanticInputCase {
        name: String,
        tx_count: usize,
        nullifier_counts_within_max: bool,
        has_zero_nullifier: bool,
        has_any_nonzero_nullifier: bool,
        has_duplicate_nonzero_nullifier: bool,
        da_encoding_valid: bool,
        parent_leaf_seeds: Vec<u64>,
        expected_commitment_seed: u64,
        message_root_seed: u64,
        expected_valid: bool,
        expected_rejection: Option<String>,
        expected_tx_statements_source: String,
        expected_start_shielded_source: String,
        expected_end_shielded_source: String,
        expected_start_kernel_source: String,
        expected_end_kernel_source: String,
        expected_nullifier_root_source: String,
        expected_da_root_source: String,
        expected_message_root_source: String,
        expected_start_tree_commitment_source: String,
        expected_end_tree_commitment_source: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTreeTransitionVectorFile {
        schema_version: u32,
        tree_transition_cases: Vec<LeanTreeTransitionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanTreeTransitionCase {
        name: String,
        tree_depth: usize,
        parent_leaf_seeds: Vec<u64>,
        tx_commitment_seed_groups: Vec<Vec<u64>>,
        proof_starting_root_source: String,
        proof_starting_root_seed: u64,
        proof_ending_root_source: String,
        proof_ending_root_seed: u64,
        apply_commitments_succeeds: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
        expected_result_root_source: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStatementAnchorAdmissionVectorFile {
        schema_version: u32,
        statement_anchor_admission_cases: Vec<LeanStatementAnchorAdmissionCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStatementAnchorAdmissionCase {
        name: String,
        tree_depth: usize,
        parent_leaf_seeds: Vec<u64>,
        tx_commitment_seed_groups: Vec<Vec<u64>>,
        tx_count: usize,
        binding_count: usize,
        anchor_sources: Vec<String>,
        anchor_source_indexes: Vec<usize>,
        anchor_seed_overrides: Vec<u64>,
        anchor_known_checks: Vec<bool>,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanProvenBatchBindingVectorFile {
        schema_version: u32,
        proven_batch_binding_cases: Vec<LeanProvenBatchBindingCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanProvenBatchBindingCase {
        name: String,
        batch_mode: String,
        proof_kind: String,
        tx_count: usize,
        expected_tx_count: usize,
        statement_commitment_matches: bool,
        da_root_matches: bool,
        da_chunk_count: u32,
        expected_da_chunk_count: u32,
        has_artifact: bool,
        artifact_kind: String,
        artifact_verifier_profile_matches: bool,
        has_receipt_root: bool,
        expected_valid: bool,
        expected_rejection: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStatementHashVectorFile {
        schema_version: u32,
        statement_hash_cases: Vec<LeanStatementHashCase>,
        #[allow(dead_code)]
        public_inputs_digest_cases: Vec<serde_json::Value>,
        #[allow(dead_code)]
        proof_digest_cases: Vec<serde_json::Value>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanStatementHashCase {
        name: String,
        merkle_root_seed: u64,
        nullifier_seeds: Vec<u64>,
        commitment_seeds: Vec<u64>,
        ciphertext_hash_seeds: Vec<u64>,
        fee: u64,
        value_balance_sign: u8,
        value_balance_magnitude: u64,
        balance_tag_seed: u64,
        circuit_version: u16,
        crypto_suite: u16,
        stablecoin_enabled: u8,
        stablecoin_asset: u64,
        stablecoin_policy_hash_seed: u64,
        stablecoin_oracle_commitment_seed: u64,
        stablecoin_attestation_commitment_seed: u64,
        stablecoin_issuance_sign: u8,
        stablecoin_issuance_magnitude: u64,
        stablecoin_policy_version: u32,
        expected_preimage_hex: String,
        expected_valid: bool,
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous_verify_mode.take() {
                Some(value) => unsafe {
                    std::env::set_var("HEGEMON_NATIVE_RECEIPT_ROOT_VERIFY_MODE", value);
                },
                None => unsafe {
                    std::env::remove_var("HEGEMON_NATIVE_RECEIPT_ROOT_VERIFY_MODE");
                },
            }
        }
    }

    fn set_native_receipt_root_verify_mode(value: &str) -> EnvGuard {
        let guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let previous_verify_mode = std::env::var("HEGEMON_NATIVE_RECEIPT_ROOT_VERIFY_MODE").ok();
        unsafe {
            std::env::set_var("HEGEMON_NATIVE_RECEIPT_ROOT_VERIFY_MODE", value);
        }
        EnvGuard {
            previous_verify_mode,
            _guard: guard,
        }
    }

    fn tx_with_commitments(commitments: Vec<[u8; 48]>) -> crate::types::Transaction {
        crate::types::Transaction::new(
            Vec::new(),
            commitments,
            [42u8; 48],
            DEFAULT_VERSION_BINDING,
            Vec::new(),
        )
    }

    fn statement_hash_tx_from_case(case: &LeanStatementHashCase) -> crate::types::Transaction {
        crate::types::Transaction::new_with_hashes(
            case.nullifier_seeds
                .iter()
                .copied()
                .map(patterned_bytes48)
                .collect(),
            case.commitment_seeds
                .iter()
                .copied()
                .map(patterned_bytes48)
                .collect(),
            patterned_bytes48(case.balance_tag_seed),
            VersionBinding::new(case.circuit_version, case.crypto_suite),
            case.ciphertext_hash_seeds
                .iter()
                .copied()
                .map(patterned_bytes48)
                .collect(),
        )
    }

    fn statement_hash_stark_inputs_from_case(
        case: &LeanStatementHashCase,
    ) -> SerializedStarkInputs {
        SerializedStarkInputs {
            input_flags: vec![1, 0],
            output_flags: vec![1, 0],
            fee: case.fee,
            value_balance_sign: case.value_balance_sign,
            value_balance_magnitude: case.value_balance_magnitude,
            merkle_root: patterned_bytes48(case.merkle_root_seed),
            balance_slot_asset_ids: vec![0, 7, u64::MAX, u64::MAX],
            stablecoin_enabled: case.stablecoin_enabled,
            stablecoin_asset_id: case.stablecoin_asset,
            stablecoin_policy_version: case.stablecoin_policy_version,
            stablecoin_issuance_sign: case.stablecoin_issuance_sign,
            stablecoin_issuance_magnitude: case.stablecoin_issuance_magnitude,
            stablecoin_policy_hash: patterned_bytes48(case.stablecoin_policy_hash_seed),
            stablecoin_oracle_commitment: patterned_bytes48(case.stablecoin_oracle_commitment_seed),
            stablecoin_attestation_commitment: patterned_bytes48(
                case.stablecoin_attestation_commitment_seed,
            ),
        }
    }

    fn patterned_bytes48(seed: u64) -> [u8; 48] {
        let mut out = [0u8; 48];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_add((index as u64).wrapping_mul(17)) as u8;
        }
        out
    }

    fn expected_hex_bytes(value: &str) -> Vec<u8> {
        let trimmed = value
            .strip_prefix("0x")
            .expect("Lean vector hex has 0x prefix");
        hex::decode(trimmed).expect("Lean vector hex decodes")
    }

    #[derive(Clone)]
    struct TestHeader {
        da_params: crate::types::DaParams,
        da_root: [u8; 48],
        message_root: [u8; 48],
    }

    impl HeaderProofExt for TestHeader {
        fn proof_commitment(&self) -> [u8; 48] {
            [0u8; 48]
        }

        fn fee_commitment(&self) -> [u8; 48] {
            [0u8; 48]
        }

        fn transaction_count(&self) -> u32 {
            0
        }

        fn version_commitment(&self) -> [u8; 48] {
            [0u8; 48]
        }

        fn da_root(&self) -> [u8; 48] {
            self.da_root
        }

        fn da_params(&self) -> crate::types::DaParams {
            self.da_params
        }

        fn kernel_root(&self) -> [u8; 48] {
            [0u8; 48]
        }

        fn message_root(&self) -> [u8; 48] {
            self.message_root
        }
    }

    fn empty_commitment_block_proof() -> CommitmentBlockProof {
        let zero = Default::default();
        let zero6 = [zero; 6];
        CommitmentBlockProof {
            proof_bytes: Vec::new(),
            proof_hash: [0u8; 48],
            public_inputs: crate::backend_interface::CommitmentBlockPublicInputs {
                tx_statements_commitment: zero6,
                starting_state_root: zero6,
                ending_state_root: zero6,
                starting_kernel_root: zero6,
                ending_kernel_root: zero6,
                nullifier_root: zero6,
                da_root: zero6,
                tx_count: 0,
                perm_alpha: zero,
                perm_beta: zero,
                nullifiers: Vec::new(),
                sorted_nullifiers: Vec::new(),
            },
        }
    }

    fn block_for_proven_batch_binding() -> (Block<TestHeader>, [u8; 48], ProofEnvelope) {
        let transactions = vec![tx_with_commitments(vec![[1u8; 48]])];
        let da_params = crate::types::DaParams {
            chunk_size: 1024,
            sample_count: 4,
        };
        let da_encoding = crate::types::encode_da_blob(&transactions, da_params).expect("da blob");
        let da_root = da_encoding.root();
        let da_chunk_count =
            u32::try_from(da_encoding.chunks().len()).expect("DA chunk count fits u32");
        let tx_statements_commitment = [0x44u8; 48];
        let verifier_profile = backend_recursive_block_profile_v2();
        let artifact = ProofEnvelope {
            kind: ProofArtifactKind::RecursiveBlockV2,
            verifier_profile,
            artifact_bytes: vec![1, 2, 3],
        };
        let block = Block {
            header: TestHeader {
                da_params,
                da_root,
                message_root: [0u8; 48],
            },
            transactions,
            coinbase: None,
            proven_batch: Some(crate::types::ProvenBatch {
                version: 2,
                tx_count: 1,
                tx_statements_commitment,
                da_root,
                da_chunk_count,
                commitment_proof: empty_commitment_block_proof(),
                mode: ProvenBatchMode::RecursiveBlock,
                proof_kind: ProofArtifactKind::RecursiveBlockV2,
                verifier_profile,
                receipt_root: None,
            }),
            block_artifact: Some(artifact.clone()),
            tx_validity_claims: None,
            tx_statements_commitment: Some(tx_statements_commitment),
            proof_verification_mode: ProofVerificationMode::SelfContainedAggregation,
        };
        (block, tx_statements_commitment, artifact)
    }

    fn sample_tx_validity_claim(seed: u64) -> TxValidityClaim {
        let statement_hash = patterned_bytes48(seed);
        TxValidityClaim::new(
            TxValidityReceipt::new(
                statement_hash,
                patterned_bytes48(seed + 1),
                patterned_bytes48(seed + 2),
                patterned_bytes48(seed + 3),
            ),
            TxStatementBinding {
                statement_hash,
                anchor: patterned_bytes48(seed + 4),
                fee: seed + 5,
                circuit_version: seed as u32 + 6,
            },
        )
    }

    fn tx_validity_claims_for_match_case(
        case: &LeanTxValidityClaimMatchCase,
    ) -> (Vec<TxValidityClaim>, Vec<TxValidityClaim>) {
        let verified = sample_tx_validity_claim(0x30);
        let mut provided = verified.clone();
        if !case.receipt_statement_hash_matches {
            provided.receipt.statement_hash = patterned_bytes48(0x80);
        }
        if !case.receipt_proof_digest_matches {
            provided.receipt.proof_digest = patterned_bytes48(0x81);
        }
        if !case.receipt_public_inputs_digest_matches {
            provided.receipt.public_inputs_digest = patterned_bytes48(0x82);
        }
        if !case.receipt_verifier_profile_matches {
            provided.receipt.verifier_profile = patterned_bytes48(0x83);
        }
        if !case.binding_statement_hash_matches {
            provided.binding.statement_hash = patterned_bytes48(0x84);
        }
        if !case.binding_anchor_root_matches {
            provided.binding.anchor = patterned_bytes48(0x85);
        }
        if !case.binding_fee_matches {
            provided.binding.fee = verified.binding.fee + 1;
        }
        if !case.binding_circuit_version_matches {
            provided.binding.circuit_version = verified.binding.circuit_version + 1;
        }

        let provided_claims = vec![provided];
        let mut verified_claims = vec![verified];
        if !case.count_matches {
            verified_claims.push(sample_tx_validity_claim(0x90));
        }
        (provided_claims, verified_claims)
    }

    fn verify_lean_tx_validity_claim_match_case(case: &LeanTxValidityClaimMatchCase) {
        let (provided, verified) = tx_validity_claims_for_match_case(case);
        let result = evaluate_tx_validity_claims_match_verified_artifacts(&provided, &verified);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{}: claim-match validity disagreed with Lean",
            case.name
        );
        let observed_rejection = result.err().map(|rejection| rejection.label().to_string());
        assert_eq!(
            observed_rejection, case.expected_rejection,
            "{}: claim-match rejection disagreed with Lean",
            case.name
        );
    }

    #[test]
    fn lean_generated_proof_policy_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PROOF_POLICY_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_PROOF_POLICY_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean proof-policy vectors");
        let vectors: LeanProofPolicyVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean proof-policy vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.proof_policy_cases.is_empty(),
            "Lean proof-policy cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.proof_policy_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_proof_policy_case(case);
        }
    }

    #[test]
    fn lean_generated_native_tx_leaf_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_NATIVE_TX_LEAF_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_NATIVE_TX_LEAF_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean native tx-leaf admission vectors");
        let vectors: LeanNativeTxLeafAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean native tx-leaf admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.native_tx_leaf_admission_cases.is_empty(),
            "Lean native tx-leaf admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.native_tx_leaf_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_native_tx_leaf_admission_case(case);
        }
    }

    #[test]
    fn lean_generated_tx_validity_claim_matching_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_TX_VALIDITY_CLAIM_MATCHING_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_TX_VALIDITY_CLAIM_MATCHING_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean tx-validity claim matching vectors");
        let vectors: LeanTxValidityClaimMatchVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean tx-validity claim matching vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.tx_validity_claim_match_cases.is_empty(),
            "Lean tx-validity claim matching cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.tx_validity_claim_match_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_tx_validity_claim_match_case(case);
        }
    }

    #[test]
    fn lean_generated_receipt_root_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_RECEIPT_ROOT_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_RECEIPT_ROOT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean receipt-root admission vectors");
        let vectors: LeanReceiptRootAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean receipt-root admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.payload_cases.is_empty(),
            "Lean receipt-root payload cases must not be empty"
        );
        assert!(
            !vectors.artifact_cases.is_empty(),
            "Lean receipt-root artifact cases must not be empty"
        );
        assert!(
            !vectors.statement_cases.is_empty(),
            "Lean receipt-root statement cases must not be empty"
        );
        assert!(
            !vectors.verified_metadata_cases.is_empty(),
            "Lean receipt-root verified-metadata cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.payload_cases {
            assert!(names.insert(format!("payload:{}", case.name)));
            verify_lean_receipt_root_payload_case(case);
        }
        for case in &vectors.artifact_cases {
            assert!(names.insert(format!("artifact:{}", case.name)));
            verify_lean_receipt_root_artifact_case(case);
        }
        for case in &vectors.statement_cases {
            assert!(names.insert(format!("statement:{}", case.name)));
            verify_lean_receipt_root_statement_case(case);
        }
        for case in &vectors.verified_metadata_cases {
            assert!(names.insert(format!("verified-metadata:{}", case.name)));
            verify_lean_receipt_root_verified_metadata_case(case);
        }
    }

    #[test]
    fn lean_generated_recursive_block_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_RECURSIVE_BLOCK_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_RECURSIVE_BLOCK_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean recursive-block admission vectors");
        let vectors: LeanRecursiveBlockAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean recursive-block admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.artifact_cases.is_empty(),
            "Lean recursive-block admission cases must not be empty"
        );
        assert!(
            !vectors.direct_verifier_cases.is_empty(),
            "Lean recursive-block direct verifier cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.artifact_cases {
            assert!(names.insert(format!("artifact:{}", case.name)));
            verify_lean_recursive_block_artifact_case(case);
        }
        for case in &vectors.direct_verifier_cases {
            assert!(names.insert(format!("direct:{}", case.name)));
            verify_lean_recursive_block_direct_verifier_case(case);
        }
    }

    #[test]
    fn lean_generated_recursive_semantic_input_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_RECURSIVE_SEMANTIC_INPUT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_RECURSIVE_SEMANTIC_INPUT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean recursive semantic input vectors");
        let vectors: LeanRecursiveSemanticInputVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean recursive semantic vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.semantic_cases.is_empty(),
            "Lean recursive semantic cases must not be empty"
        );

        for case in &vectors.semantic_cases {
            verify_lean_recursive_semantic_input_case(case);
        }
    }

    #[test]
    fn lean_generated_tree_transition_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_TREE_TRANSITION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_TREE_TRANSITION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean tree-transition vectors");
        let vectors: LeanTreeTransitionVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean tree-transition vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.tree_transition_cases.is_empty(),
            "Lean tree-transition cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.tree_transition_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_tree_transition_case(case);
        }
    }

    #[test]
    fn lean_generated_statement_anchor_admission_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_STATEMENT_ANCHOR_ADMISSION_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_STATEMENT_ANCHOR_ADMISSION_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean statement-anchor admission vectors");
        let vectors: LeanStatementAnchorAdmissionVectorFile = serde_json::from_str(&raw)
            .expect("parse generated Lean statement-anchor admission vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.statement_anchor_admission_cases.is_empty(),
            "Lean statement-anchor admission cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.statement_anchor_admission_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_statement_anchor_admission_case(case);
        }
    }

    #[test]
    fn lean_generated_proven_batch_binding_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_PROVEN_BATCH_BINDING_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_PROVEN_BATCH_BINDING_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw = std::fs::read_to_string(&path)
            .expect("read generated Lean proven-batch binding vectors");
        let vectors: LeanProvenBatchBindingVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean proven-batch binding vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.proven_batch_binding_cases.is_empty(),
            "Lean proven-batch binding cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.proven_batch_binding_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_proven_batch_binding_case(case);
        }
    }

    #[test]
    fn lean_generated_statement_hash_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_STATEMENT_HASH_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_STATEMENT_HASH_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean statement-hash vectors");
        let vectors: LeanStatementHashVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean statement-hash vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.statement_hash_cases.is_empty(),
            "Lean statement-hash cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.statement_hash_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_statement_hash_case(case);
        }
    }

    fn verify_lean_tree_transition_case(case: &LeanTreeTransitionCase) {
        let parent_tree = tree_transition_parent_tree(case);
        let transactions = tree_transition_transactions_from_case(case);
        let applied_tree = apply_commitments(&parent_tree, &transactions);
        assert_eq!(
            applied_tree.is_ok(),
            case.apply_commitments_succeeds,
            "{} commitment application drifted from Lean vector setup: {applied_tree:?}",
            case.name
        );

        let proof_starting_root = tree_transition_root_from_source(
            &case.proof_starting_root_source,
            case.proof_starting_root_seed,
            &parent_tree,
            applied_tree.as_ref().ok(),
        );
        let proof_ending_root = tree_transition_root_from_source(
            &case.proof_ending_root_source,
            case.proof_ending_root_seed,
            &parent_tree,
            applied_tree.as_ref().ok(),
        );
        let result = verify_and_apply_tree_transition_without_anchors(
            &parent_tree,
            proof_starting_root,
            proof_ending_root,
            &transactions,
        );
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} tree-transition validity drifted from Lean spec: {result:?}",
            case.name
        );
        let actual_rejection = result
            .as_ref()
            .err()
            .map(tree_transition_error_label)
            .map(str::to_string);
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} tree-transition rejection label drifted from Lean spec",
            case.name
        );

        if let Ok(updated_tree) = result {
            assert_eq!(
                case.expected_result_root_source.as_deref(),
                Some("applied_commitment_tree_root"),
                "{} accepted tree-transition vector must name the applied root source",
                case.name
            );
            let expected_tree = applied_tree.expect("accepted Lean tree-transition applies");
            assert_eq!(
                updated_tree.root(),
                expected_tree.root(),
                "{} accepted tree-transition root no longer matches applied tree",
                case.name
            );
            assert_eq!(
                updated_tree.leaf_count(),
                expected_tree.leaf_count(),
                "{} accepted tree-transition leaf count no longer matches applied tree",
                case.name
            );
        }
    }

    fn tree_transition_parent_tree(case: &LeanTreeTransitionCase) -> CommitmentTreeState {
        let mut tree = CommitmentTreeState::new_empty(
            case.tree_depth,
            crate::commitment_tree::DEFAULT_ROOT_HISTORY_LIMIT,
        )
        .expect("Lean tree-transition depth is valid");
        for seed in &case.parent_leaf_seeds {
            tree.append(patterned_bytes48(*seed))
                .expect("Lean parent leaf seed fits tree");
        }
        tree
    }

    fn tree_transition_transactions_from_case(
        case: &LeanTreeTransitionCase,
    ) -> Vec<crate::types::Transaction> {
        case.tx_commitment_seed_groups
            .iter()
            .map(|group| {
                let commitments = group
                    .iter()
                    .map(|seed| {
                        if *seed == 0 {
                            [0u8; 48]
                        } else {
                            patterned_bytes48(*seed)
                        }
                    })
                    .collect();
                tx_with_commitments(commitments)
            })
            .collect()
    }

    fn tree_transition_root_from_source(
        source: &str,
        seed: u64,
        parent_tree: &CommitmentTreeState,
        applied_tree: Option<&CommitmentTreeState>,
    ) -> [u8; 48] {
        match source {
            "parent_tree_root" => parent_tree.root(),
            "applied_commitment_tree_root" => applied_tree
                .expect("Lean vector requested applied root after successful application")
                .root(),
            "patterned_seed" => patterned_bytes48(seed),
            other => panic!("unknown Lean tree-transition root source {other}"),
        }
    }

    fn tree_transition_error_label(error: &ProofError) -> &'static str {
        match error {
            ProofError::StartingRootMismatch { .. } => "starting_root_mismatch",
            ProofError::CommitmentTree(_) => "apply_failed",
            ProofError::EndingRootMismatch { .. } => "ending_root_mismatch",
            other => panic!("unexpected tree-transition error for Lean vector: {other:?}"),
        }
    }

    fn verify_lean_statement_anchor_admission_case(case: &LeanStatementAnchorAdmissionCase) {
        let parent_tree = statement_anchor_parent_tree(case);
        let transactions = statement_anchor_transactions_from_case(case);
        assert_eq!(
            transactions.len(),
            case.tx_count,
            "{} tx_count no longer matches generated transaction set",
            case.name
        );
        assert_eq!(
            case.anchor_known_checks.len(),
            case.binding_count,
            "{} anchor_known_checks must model every binding",
            case.name
        );
        assert_eq!(
            case.anchor_sources.len(),
            case.binding_count,
            "{} anchor_sources must model every binding",
            case.name
        );
        assert_eq!(
            case.anchor_source_indexes.len(),
            case.binding_count,
            "{} anchor_source_indexes must model every binding",
            case.name
        );
        assert_eq!(
            case.anchor_seed_overrides.len(),
            case.binding_count,
            "{} anchor_seed_overrides must model every binding",
            case.name
        );

        let bindings = statement_anchor_bindings_from_case(case, &parent_tree, &transactions);
        let result = validate_statement_anchor_history(&parent_tree, case.tx_count, &bindings);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} statement-anchor admission validity drifted from Lean spec: {result:?}",
            case.name
        );
        let actual_rejection = result
            .as_ref()
            .err()
            .map(statement_anchor_admission_error_label)
            .map(str::to_string);
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} statement-anchor admission rejection label drifted from Lean spec",
            case.name
        );
    }

    fn statement_anchor_parent_tree(
        case: &LeanStatementAnchorAdmissionCase,
    ) -> CommitmentTreeState {
        let mut tree = CommitmentTreeState::new_empty(
            case.tree_depth,
            crate::commitment_tree::DEFAULT_ROOT_HISTORY_LIMIT,
        )
        .expect("Lean statement-anchor depth is valid");
        for seed in &case.parent_leaf_seeds {
            tree.append(patterned_bytes48(*seed))
                .expect("Lean parent leaf seed fits tree");
        }
        tree
    }

    fn statement_anchor_transactions_from_case(
        case: &LeanStatementAnchorAdmissionCase,
    ) -> Vec<crate::types::Transaction> {
        case.tx_commitment_seed_groups
            .iter()
            .map(|group| {
                let commitments = group
                    .iter()
                    .map(|seed| {
                        if *seed == 0 {
                            [0u8; 48]
                        } else {
                            patterned_bytes48(*seed)
                        }
                    })
                    .collect();
                tx_with_commitments(commitments)
            })
            .collect()
    }

    fn statement_anchor_bindings_from_case(
        case: &LeanStatementAnchorAdmissionCase,
        parent_tree: &CommitmentTreeState,
        transactions: &[crate::types::Transaction],
    ) -> Vec<TxStatementBinding> {
        case.anchor_sources
            .iter()
            .enumerate()
            .map(|(binding_index, source)| {
                let anchor = statement_anchor_from_source(
                    source,
                    case.anchor_source_indexes[binding_index],
                    case.anchor_seed_overrides[binding_index],
                    parent_tree,
                    transactions,
                );
                statement_anchor_binding(anchor)
            })
            .collect()
    }

    fn statement_anchor_from_source(
        source: &str,
        source_index: usize,
        seed: u64,
        parent_tree: &CommitmentTreeState,
        transactions: &[crate::types::Transaction],
    ) -> [u8; 48] {
        match source {
            "parent_tree_root" => parent_tree.root(),
            "parent_history_index" => *parent_tree
                .root_history()
                .nth(source_index)
                .expect("Lean vector requested existing parent history index"),
            "after_tx_index" => {
                let mut tree = parent_tree.clone();
                for tx in transactions.iter().take(source_index + 1) {
                    for commitment in tx.commitments.iter().copied().filter(|c| *c != [0u8; 48]) {
                        tree.append(commitment)
                            .expect("Lean same-block transaction commitment fits tree");
                    }
                }
                tree.root()
            }
            "patterned_seed" => patterned_bytes48(seed),
            other => panic!("unknown Lean statement-anchor source {other}"),
        }
    }

    fn statement_anchor_admission_error_label(error: &ProofError) -> &'static str {
        match error {
            ProofError::CommitmentProofInputsMismatch(message)
                if message.contains("statement binding count mismatch") =>
            {
                "binding_count_mismatch"
            }
            ProofError::InvalidAnchor { .. } => "unknown_anchor",
            other => {
                panic!("unexpected statement-anchor admission error for Lean vector: {other:?}")
            }
        }
    }

    fn statement_anchor_binding(anchor: [u8; 48]) -> TxStatementBinding {
        TxStatementBinding {
            statement_hash: [11u8; 48],
            anchor,
            fee: 0,
            circuit_version: 1,
        }
    }

    fn verify_lean_statement_hash_case(case: &LeanStatementHashCase) {
        let tx = statement_hash_tx_from_case(case);
        let stark_inputs = statement_hash_stark_inputs_from_case(case);
        let actual_hash = statement_hash_from_tx_and_stark_inputs(&tx, &stark_inputs);
        assert_eq!(
            actual_hash.is_ok(),
            case.expected_valid,
            "{} statement hash validity drifted from Lean spec: {actual_hash:?}",
            case.name
        );

        let value_balance = decode_signed_magnitude(
            stark_inputs.value_balance_sign,
            stark_inputs.value_balance_magnitude,
            "value_balance",
        );
        let stablecoin_issuance = decode_signed_magnitude(
            stark_inputs.stablecoin_issuance_sign,
            stark_inputs.stablecoin_issuance_magnitude,
            "stablecoin_issuance",
        );
        let actual_preimage = match (value_balance, stablecoin_issuance) {
            (Ok(value_balance), Ok(stablecoin_issuance)) => {
                crate::backend_interface::transaction_statement_preimage_from_parts(
                    &stark_inputs.merkle_root,
                    &tx.nullifiers,
                    &tx.commitments,
                    &tx.ciphertext_hashes,
                    stark_inputs.fee,
                    value_balance,
                    &tx.balance_tag,
                    tx.version.circuit,
                    tx.version.crypto,
                    stark_inputs.stablecoin_enabled,
                    stark_inputs.stablecoin_asset_id,
                    &stark_inputs.stablecoin_policy_hash,
                    &stark_inputs.stablecoin_oracle_commitment,
                    &stark_inputs.stablecoin_attestation_commitment,
                    stablecoin_issuance,
                    stark_inputs.stablecoin_policy_version,
                )
            }
            (Err(message), _) | (_, Err(message)) => {
                Err(transaction_circuit::TransactionCircuitError::ConstraintViolationOwned(message))
            }
        };
        assert_eq!(
            actual_preimage.is_ok(),
            case.expected_valid,
            "{} statement preimage validity drifted from Lean spec: {actual_preimage:?}",
            case.name
        );

        if case.expected_valid {
            let actual_preimage = actual_preimage.expect("valid Lean statement preimage");
            let expected_preimage = expected_hex_bytes(&case.expected_preimage_hex);
            assert_eq!(
                actual_preimage, expected_preimage,
                "{} statement preimage bytes drifted from Lean spec",
                case.name
            );
            assert_eq!(
                actual_hash.expect("valid statement hash"),
                blake3_384(&expected_preimage),
                "{} statement hash digest no longer hashes the checked preimage",
                case.name
            );
        }
    }

    fn verify_lean_proof_policy_case(case: &LeanProofPolicyCase) {
        let input = BlockProofPolicyInput {
            tx_count: case.tx_count,
            verification_mode: parse_lean_verification_mode(&case.verification_mode),
            has_proven_batch: case.has_proven_batch,
            proven_batch_mode: parse_lean_batch_mode(&case.batch_mode),
            commitment_proof_bytes: case.commitment_proof_bytes,
            has_block_artifact: case.has_block_artifact,
            has_receipt_root: case.has_receipt_root,
            has_tx_validity_artifacts: case.has_tx_validity_artifacts,
            tx_validity_artifact_count: case.tx_validity_artifact_count,
            has_tx_validity_claims: case.has_tx_validity_claims,
        };
        let result = evaluate_block_proof_policy(input);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} proof policy validity drifted from Lean spec",
            case.name
        );
        let actual_rejection = result.err().map(|rejection| rejection.label().to_string());
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} proof policy rejection label drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_native_tx_leaf_admission_case(case: &LeanNativeTxLeafAdmissionCase) {
        let input = NativeTxLeafAdmissionInput {
            has_envelope: case.has_envelope,
            envelope_kind: parse_lean_proof_artifact_kind(&case.envelope_kind),
            envelope_verifier_profile_matches: case.envelope_verifier_profile_matches,
            artifact_bytes_len: case.artifact_bytes_len,
            max_artifact_bytes: case.max_artifact_bytes,
            receipt_verifier_profile_matches: case.receipt_verifier_profile_matches,
            has_expected_artifact_hash: case.has_expected_artifact_hash,
            expected_artifact_hash_matches: case.expected_artifact_hash_matches,
            has_cache_entry: case.has_cache_entry,
            cache_receipt_matches: case.cache_receipt_matches,
            cache_transaction_matches: case.cache_transaction_matches,
        };
        let result = evaluate_native_tx_leaf_admission(input);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} native tx-leaf admission validity drifted from Lean spec",
            case.name
        );
        let actual_rejection = result
            .as_ref()
            .err()
            .map(|rejection| rejection.label().to_string());
        let actual_outcome = result.ok().map(|outcome| outcome.label().to_string());
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} native tx-leaf admission rejection label drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual_outcome.as_deref(),
            case.expected_outcome.as_deref(),
            "{} native tx-leaf admission outcome label drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_receipt_root_payload_case(case: &LeanReceiptRootPayloadCase) {
        let input = ReceiptRootPayloadAdmissionInput {
            payload_leaf_count_matches: case.payload_leaf_count_matches,
            payload_receipt_count_matches: case.payload_receipt_count_matches,
            has_claim_receipts: case.has_claim_receipts,
            payload_receipts_match_claims: case.payload_receipts_match_claims,
            has_tx_artifacts: case.has_tx_artifacts,
        };
        let result = evaluate_receipt_root_payload_admission(input);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} receipt-root payload admission validity drifted from Lean spec",
            case.name
        );
        let actual_rejection = result.err().map(|rejection| rejection.label().to_string());
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} receipt-root payload admission rejection label drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_receipt_root_artifact_case(case: &LeanReceiptRootArtifactCase) {
        let input = ReceiptRootArtifactAdmissionInput {
            envelope_kind: parse_lean_proof_artifact_kind(&case.envelope_kind),
            envelope_verifier_profile_matches: case.envelope_verifier_profile_matches,
            artifact_bytes_len: case.artifact_bytes_len,
            max_artifact_bytes: case.max_artifact_bytes,
            has_tx_artifacts: case.has_tx_artifacts,
            tx_artifact_count_matches: case.tx_artifact_count_matches,
        };
        let result = evaluate_receipt_root_artifact_admission(input);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} receipt-root artifact admission validity drifted from Lean spec",
            case.name
        );
        let actual_rejection = result.err().map(|rejection| rejection.label().to_string());
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} receipt-root artifact admission rejection label drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_receipt_root_statement_case(case: &LeanReceiptRootStatementCase) {
        let input = ReceiptRootStatementBindingInput {
            statement_commitment_matches: case.statement_commitment_matches,
        };
        let result = evaluate_receipt_root_statement_binding(input);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} receipt-root statement binding validity drifted from Lean spec",
            case.name
        );
        let actual_rejection = result.err().map(|rejection| rejection.label().to_string());
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} receipt-root statement binding rejection label drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_receipt_root_verified_metadata_case(case: &LeanReceiptRootVerifiedMetadataCase) {
        let input = ReceiptRootVerifiedMetadataInput {
            verified_leaf_count_matches: case.verified_leaf_count_matches,
        };
        let result = evaluate_receipt_root_verified_metadata(input);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} receipt-root verified metadata validity drifted from Lean spec",
            case.name
        );
        let actual_rejection = result.err().map(|rejection| rejection.label().to_string());
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} receipt-root verified metadata rejection label drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_recursive_block_artifact_case(case: &LeanRecursiveBlockArtifactCase) {
        let input = RecursiveBlockArtifactAdmissionInput {
            expected_kind: parse_lean_proof_artifact_kind(&case.expected_kind),
            envelope_kind: parse_lean_proof_artifact_kind(&case.envelope_kind),
            verifier_profile_matches: case.verifier_profile_matches,
            artifact_bytes_len: case.artifact_bytes_len,
            max_artifact_bytes: case.max_artifact_bytes,
            artifact_decoded: case.artifact_decoded,
            header_version_matches: case.header_version_matches,
            tx_count_matches: case.tx_count_matches,
            statement_commitment_matches: case.statement_commitment_matches,
            public_replay_matches: case.public_replay_matches,
        };
        let result = evaluate_recursive_block_artifact_admission(input);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} recursive-block admission validity drifted from Lean spec",
            case.name
        );
        let actual_rejection = result.err().map(|rejection| rejection.label().to_string());
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} recursive-block admission rejection label drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_recursive_block_direct_verifier_case(
        case: &LeanRecursiveBlockDirectVerifierCase,
    ) {
        let kind = parse_lean_proof_artifact_kind(&case.kind);
        let (verifier_profile, artifact_bytes) = match kind {
            ProofArtifactKind::RecursiveBlockV1 => (
                backend_recursive_block_profile_v1(),
                crate::backend_interface::serialize_recursive_block_artifact_v1(
                    &sample_recursive_block_artifact_v1(1),
                )
                .expect("serialize recursive_block_v1 artifact"),
            ),
            ProofArtifactKind::RecursiveBlockV2 => (
                backend_recursive_block_profile_v2(),
                crate::backend_interface::serialize_recursive_block_artifact_v2(
                    &sample_recursive_block_artifact_v2(1),
                )
                .expect("serialize recursive_block_v2 artifact"),
            ),
            other => panic!(
                "unexpected Lean recursive direct verifier kind {}",
                other.label()
            ),
        };
        let verifier = RecursiveBlockVerifier { kind };
        let envelope = ProofEnvelope {
            kind,
            verifier_profile,
            artifact_bytes,
        };
        let result = verifier.verify_block_artifact(
            &[tx_with_commitments(vec![])],
            None,
            &[0u8; 48],
            &envelope,
        );
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} direct recursive verifier validity drifted from Lean spec: {result:?}",
            case.name
        );
        let actual_rejection = result
            .as_ref()
            .err()
            .map(recursive_block_direct_verifier_error_label)
            .map(str::to_string);
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} direct recursive verifier rejection label drifted from Lean spec",
            case.name
        );
    }

    fn recursive_block_direct_verifier_error_label(error: &ProofError) -> &'static str {
        match error {
            ProofError::UnsupportedProofArtifact(message)
                if message.contains("verified-record semantic replay") =>
            {
                "requires_semantic_replay"
            }
            other => {
                panic!("unexpected direct recursive verifier error for Lean vector: {other:?}")
            }
        }
    }

    fn verify_lean_recursive_semantic_input_case(case: &LeanRecursiveSemanticInputCase) {
        assert_eq!(case.expected_tx_statements_source, "expected_commitment");
        assert_eq!(case.expected_start_shielded_source, "parent_tree_root");
        assert_eq!(
            case.expected_end_shielded_source,
            "applied_commitment_tree_root"
        );
        assert_eq!(
            case.expected_start_kernel_source,
            "kernel_root(parent_tree_root)"
        );
        assert_eq!(
            case.expected_end_kernel_source,
            "kernel_root(applied_commitment_tree_root)"
        );
        assert_eq!(case.expected_nullifier_root_source, "nonzero_nullifier_set");
        assert_eq!(
            case.expected_da_root_source,
            "block_transactions_and_header_da_params"
        );
        assert_eq!(case.expected_message_root_source, "header_message_root");
        assert_eq!(
            case.expected_start_tree_commitment_source,
            "parent_tree_recursive_state"
        );
        assert_eq!(
            case.expected_end_tree_commitment_source,
            "applied_tree_recursive_state"
        );

        let parent_tree = recursive_semantic_parent_tree(case);
        let transactions = recursive_semantic_transactions_from_case(case);
        let da_params = if case.da_encoding_valid {
            crate::types::DaParams {
                chunk_size: 64,
                sample_count: 1,
            }
        } else {
            crate::types::DaParams {
                chunk_size: 0,
                sample_count: 1,
            }
        };
        let header_da_root = da_root(&transactions, da_params).unwrap_or([0u8; 48]);
        let message_root = patterned_bytes48(case.message_root_seed);
        let block = Block {
            header: TestHeader {
                da_params,
                da_root: header_da_root,
                message_root,
            },
            transactions,
            coinbase: None,
            proven_batch: None,
            block_artifact: None,
            tx_validity_claims: None,
            tx_statements_commitment: None,
            proof_verification_mode: ProofVerificationMode::SelfContainedAggregation,
        };
        let expected_commitment = patterned_bytes48(case.expected_commitment_seed);
        let result =
            recursive_block_semantic_inputs_from_block(&block, &parent_tree, expected_commitment);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} recursive semantic validity drifted from Lean spec: {result:?}",
            case.name
        );
        let actual_rejection = result
            .as_ref()
            .err()
            .map(recursive_semantic_error_label)
            .map(str::to_string);
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} recursive semantic rejection label drifted from Lean spec",
            case.name
        );

        if let Ok(semantic) = result {
            let expected_tree = apply_commitments(&parent_tree, &block.transactions)
                .expect("valid Lean semantic case applies commitments");
            let nullifier_lists = commitment_nullifier_lists(&block.transactions)
                .expect("valid Lean semantic case has nullifiers");
            let expected_nullifier_root = nullifier_root_from_list(&nullifier_lists.nullifiers)
                .expect("valid Lean semantic case has unique nullifiers");
            let expected_da_root = da_root(&block.transactions, block.header.da_params())
                .expect("valid Lean semantic case has DA root");
            assert_eq!(semantic.tx_statements_commitment, expected_commitment);
            assert_eq!(semantic.start_shielded_root, parent_tree.root());
            assert_eq!(semantic.end_shielded_root, expected_tree.root());
            assert_eq!(
                semantic.start_kernel_root,
                kernel_root_from_shielded_root(&parent_tree.root())
            );
            assert_eq!(
                semantic.end_kernel_root,
                kernel_root_from_shielded_root(&expected_tree.root())
            );
            assert_eq!(semantic.nullifier_root, expected_nullifier_root);
            assert_eq!(semantic.da_root, expected_da_root);
            assert_eq!(semantic.message_root, message_root);
            assert_eq!(
                semantic.start_tree_commitment,
                parent_tree.recursive_state_commitment()
            );
            assert_eq!(
                semantic.end_tree_commitment,
                expected_tree.recursive_state_commitment()
            );
        }
    }

    fn recursive_semantic_error_label(error: &ProofError) -> &'static str {
        match error {
            ProofError::CommitmentProofEmptyBlock => "empty_block",
            ProofError::DaEncoding(_) => "da_encoding",
            ProofError::CommitmentProofInputsMismatch(message)
                if message.contains("exceeds MAX_INPUTS") =>
            {
                "excessive_nullifiers"
            }
            ProofError::CommitmentProofInputsMismatch(message)
                if message.contains("includes zero nullifier") =>
            {
                "zero_nullifier"
            }
            ProofError::CommitmentProofInputsMismatch(message)
                if message.contains("must include at least one non-zero") =>
            {
                "missing_nonzero_nullifier"
            }
            ProofError::CommitmentProofInputsMismatch(message)
                if message.contains("duplicate nullifier") =>
            {
                "duplicate_nullifier"
            }
            other => panic!("unexpected recursive semantic error for Lean vector: {other:?}"),
        }
    }

    fn recursive_semantic_parent_tree(
        case: &LeanRecursiveSemanticInputCase,
    ) -> CommitmentTreeState {
        let mut tree = CommitmentTreeState::default();
        for seed in &case.parent_leaf_seeds {
            tree.append(patterned_bytes48(*seed))
                .expect("Lean parent leaf seed fits default commitment tree");
        }
        tree
    }

    fn recursive_semantic_transactions_from_case(
        case: &LeanRecursiveSemanticInputCase,
    ) -> Vec<crate::types::Transaction> {
        (0..case.tx_count)
            .map(|index| recursive_semantic_transaction_from_case(case, index))
            .collect()
    }

    fn recursive_semantic_transaction_from_case(
        case: &LeanRecursiveSemanticInputCase,
        index: usize,
    ) -> crate::types::Transaction {
        let mut nullifiers = Vec::new();
        if case.nullifier_counts_within_max {
            if case.has_zero_nullifier && index == 0 {
                nullifiers.push([0u8; 48]);
            }
            if case.has_any_nonzero_nullifier {
                let seed = if case.has_duplicate_nonzero_nullifier {
                    0x77
                } else {
                    0x100 + index as u64
                };
                nullifiers.push(patterned_bytes48(seed));
            }
        } else if index == 0 {
            nullifiers.extend(
                (0..=transaction_circuit::constants::MAX_INPUTS)
                    .map(|offset| patterned_bytes48(0x180 + offset as u64)),
            );
        }

        crate::types::Transaction::new(
            nullifiers,
            vec![patterned_bytes48(0x200 + index as u64)],
            patterned_bytes48(0x300 + index as u64),
            DEFAULT_VERSION_BINDING,
            vec![vec![
                (0x40 + index as u8),
                (0x50 + index as u8),
                (0x60 + index as u8),
            ]],
        )
    }

    fn verify_lean_proven_batch_binding_case(case: &LeanProvenBatchBindingCase) {
        let input = ProvenBatchBindingInput {
            proven_batch_mode: parse_lean_batch_mode(&case.batch_mode),
            proof_kind: parse_lean_proof_artifact_kind(&case.proof_kind),
            tx_count: case.tx_count,
            expected_tx_count: case.expected_tx_count,
            statement_commitment_matches: case.statement_commitment_matches,
            da_root_matches: case.da_root_matches,
            da_chunk_count: case.da_chunk_count,
            expected_da_chunk_count: case.expected_da_chunk_count,
            artifact_kind: case
                .has_artifact
                .then(|| parse_lean_proof_artifact_kind(&case.artifact_kind)),
            artifact_verifier_profile_matches: case.artifact_verifier_profile_matches,
            has_receipt_root: case.has_receipt_root,
        };
        let result = evaluate_proven_batch_binding(input);
        assert_eq!(
            result.is_ok(),
            case.expected_valid,
            "{} proven-batch binding validity drifted from Lean spec",
            case.name
        );
        let actual_rejection = result.err().map(|rejection| rejection.label().to_string());
        assert_eq!(
            actual_rejection.as_deref(),
            case.expected_rejection.as_deref(),
            "{} proven-batch binding rejection label drifted from Lean spec",
            case.name
        );
    }

    fn parse_lean_verification_mode(value: &str) -> ProofVerificationMode {
        match value {
            "inline_required" => ProofVerificationMode::InlineRequired,
            "self_contained" => ProofVerificationMode::SelfContainedAggregation,
            other => panic!("unknown Lean proof verification mode {other}"),
        }
    }

    fn parse_lean_batch_mode(value: &str) -> ProvenBatchMode {
        match value {
            "inline_tx" => ProvenBatchMode::InlineTx,
            "receipt_root" => ProvenBatchMode::ReceiptRoot,
            "recursive_block" => ProvenBatchMode::RecursiveBlock,
            other => panic!("unknown Lean proven batch mode {other}"),
        }
    }

    fn parse_lean_proof_artifact_kind(value: &str) -> ProofArtifactKind {
        match value {
            "inline_tx" => ProofArtifactKind::InlineTx,
            "tx_leaf" => ProofArtifactKind::TxLeaf,
            "receipt_root" => ProofArtifactKind::ReceiptRoot,
            "recursive_block_v1" => ProofArtifactKind::RecursiveBlockV1,
            "recursive_block_v2" => ProofArtifactKind::RecursiveBlockV2,
            other => panic!("unknown Lean proof artifact kind {other}"),
        }
    }

    #[test]
    fn proven_batch_binding_rejects_tx_count_mismatch() {
        let (mut block, expected_commitment, artifact) = block_for_proven_batch_binding();
        let mut batch = block.proven_batch.clone().expect("batch");
        batch.tx_count = 2;
        block.proven_batch = Some(batch.clone());

        let err =
            validate_proven_batch_binding(&block, &batch, &expected_commitment, Some(&artifact))
                .expect_err("tx_count mismatch must fail");
        assert!(matches!(err, ProofError::ProvenBatchBindingMismatch(_)));
    }

    #[test]
    fn proven_batch_binding_rejects_da_root_mismatch() {
        let (mut block, expected_commitment, artifact) = block_for_proven_batch_binding();
        let mut batch = block.proven_batch.clone().expect("batch");
        batch.da_root[0] ^= 0x5a;
        block.proven_batch = Some(batch.clone());

        let err =
            validate_proven_batch_binding(&block, &batch, &expected_commitment, Some(&artifact))
                .expect_err("DA root mismatch must fail");
        assert!(matches!(err, ProofError::ProvenBatchBindingMismatch(_)));
    }

    #[test]
    fn proven_batch_binding_rejects_da_chunk_count_mismatch() {
        let (mut block, expected_commitment, artifact) = block_for_proven_batch_binding();
        let mut batch = block.proven_batch.clone().expect("batch");
        batch.da_chunk_count = batch.da_chunk_count.saturating_add(1).max(1);
        block.proven_batch = Some(batch.clone());

        let err =
            validate_proven_batch_binding(&block, &batch, &expected_commitment, Some(&artifact))
                .expect_err("DA chunk count mismatch must fail");
        match err {
            ProofError::ProvenBatchBindingMismatch(message) => {
                assert!(
                    message.contains("DA chunk count mismatch"),
                    "unexpected proven-batch binding error: {message}"
                );
            }
            other => panic!("unexpected proven-batch binding error: {other:?}"),
        }
    }

    #[test]
    fn proven_batch_binding_rejects_artifact_route_mismatch() {
        let (block, expected_commitment, mut artifact) = block_for_proven_batch_binding();
        let batch = block.proven_batch.clone().expect("batch");
        artifact.kind = ProofArtifactKind::RecursiveBlockV1;

        let err =
            validate_proven_batch_binding(&block, &batch, &expected_commitment, Some(&artifact))
                .expect_err("artifact kind mismatch must fail");
        assert!(matches!(err, ProofError::ProvenBatchBindingMismatch(_)));
    }

    #[test]
    fn proven_batch_binding_rejects_missing_recursive_block_artifact() {
        let (block, expected_commitment, _) = block_for_proven_batch_binding();
        let batch = block.proven_batch.clone().expect("batch");

        let err = validate_proven_batch_binding(&block, &batch, &expected_commitment, None)
            .expect_err("recursive block binding must require block artifact");
        match err {
            ProofError::ProvenBatchBindingMismatch(message) => {
                assert!(
                    message.contains("requires block artifact"),
                    "unexpected proven-batch binding error: {message}"
                );
            }
            other => panic!("unexpected proven-batch binding error: {other:?}"),
        }
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

    #[test]
    fn statement_anchor_history_accepts_parent_root_anchor() {
        let parent_tree = CommitmentTreeState::default();
        let bindings = vec![statement_anchor_binding(parent_tree.root())];
        validate_statement_anchor_history(&parent_tree, 1, &bindings)
            .expect("parent root is an admitted transaction anchor");
    }

    #[test]
    fn statement_anchor_history_accepts_retained_parent_history_anchor() {
        let mut parent_tree = CommitmentTreeState::default();
        let historical_root = parent_tree.root();
        parent_tree
            .append([3u8; 48])
            .expect("test commitment fits tree");
        let bindings = vec![statement_anchor_binding(historical_root)];
        validate_statement_anchor_history(&parent_tree, 1, &bindings)
            .expect("retained parent root history is admitted");
    }

    #[test]
    fn statement_anchor_history_rejects_unknown_anchor() {
        let parent_tree = CommitmentTreeState::default();
        let bindings = vec![statement_anchor_binding([7u8; 48])];
        let err = validate_statement_anchor_history(&parent_tree, 1, &bindings)
            .expect_err("unknown anchor must fail");
        assert!(matches!(err, ProofError::InvalidAnchor { index: 0, .. }));
    }

    #[test]
    fn statement_anchor_history_rejects_anchor_known_only_after_same_block_append() {
        let parent_tree = CommitmentTreeState::default();
        let txs = [
            tx_with_commitments(vec![[1u8; 48]]),
            tx_with_commitments(vec![[2u8; 48]]),
        ];
        let mut after_first_tx = parent_tree.clone();
        after_first_tx
            .append([1u8; 48])
            .expect("test commitment fits tree");
        let bindings = vec![
            statement_anchor_binding(parent_tree.root()),
            statement_anchor_binding(after_first_tx.root()),
        ];

        let err = validate_statement_anchor_history(&parent_tree, txs.len(), &bindings)
            .expect_err("same-block anchor must not be admitted");
        assert!(matches!(err, ProofError::InvalidAnchor { index: 1, .. }));
    }

    #[test]
    fn statement_anchor_history_rejects_binding_count_mismatch_before_anchor_lookup() {
        let parent_tree = CommitmentTreeState::default();
        let bindings = vec![statement_anchor_binding([7u8; 48])];
        let err = validate_statement_anchor_history(&parent_tree, 2, &bindings)
            .expect_err("binding count mismatch must fail first");
        assert!(matches!(err, ProofError::CommitmentProofInputsMismatch(_)));
    }

    #[test]
    fn provided_claims_must_match_verified_artifacts_exactly() {
        let provided = vec![TxValidityClaim::new(
            TxValidityReceipt::new([1u8; 48], [2u8; 48], [3u8; 48], [4u8; 48]),
            TxStatementBinding {
                statement_hash: [1u8; 48],
                anchor: [5u8; 48],
                fee: 7,
                circuit_version: 9,
            },
        )];
        let mut verified = provided.clone();
        verified[0].receipt.proof_digest[0] ^= 0x5a;

        let err = ensure_claims_match_verified_artifacts(&provided, &verified)
            .expect_err("tampered receipt fields must fail closed");
        assert!(matches!(err, ProofError::AggregationProofInputsMismatch(_)));
    }

    #[test]
    fn exact_claim_match_is_accepted() {
        let provided = vec![TxValidityClaim::new(
            TxValidityReceipt::new([1u8; 48], [2u8; 48], [3u8; 48], [4u8; 48]),
            TxStatementBinding {
                statement_hash: [1u8; 48],
                anchor: [5u8; 48],
                fee: 7,
                circuit_version: 9,
            },
        )];

        ensure_claims_match_verified_artifacts(&provided, &provided)
            .expect("identical verified claims must be accepted");
    }

    fn malformed_inline_tx_proof_with_oversized_public_inputs() -> TransactionProof {
        let mut public_inputs = transaction_circuit::TransactionPublicInputs::default();
        public_inputs
            .nullifiers
            .resize(MAX_INPUTS.saturating_add(1), [9u8; 48]);
        TransactionProof {
            nullifiers: public_inputs.nullifiers.clone(),
            commitments: public_inputs.commitments.clone(),
            balance_slots: public_inputs.balance_slots.clone(),
            public_inputs,
            backend: protocol_versioning::TxProofBackend::Plonky3Fri,
            stark_proof: vec![1, 2, 3, 4],
            stark_public_inputs: None,
        }
    }

    #[test]
    fn tx_validity_receipt_rejects_oversized_public_inputs_without_panic() {
        let proof = malformed_inline_tx_proof_with_oversized_public_inputs();

        let err = tx_validity_receipt_from_proof(&proof)
            .expect_err("oversized public inputs must be a structured receipt error");
        assert!(err.contains("transaction nullifier length"));
    }

    #[test]
    fn tx_validity_claim_derivation_rejects_malformed_inline_public_inputs_without_panic() {
        let proof = malformed_inline_tx_proof_with_oversized_public_inputs();
        let artifact_bytes = bincode::serialize(&proof).expect("serialize malformed proof");
        let tx = tx_with_commitments(Vec::new());
        let expected_profile = transaction_verifier_profile_digest_for_version(tx.version);
        let artifact = TxValidityArtifact {
            receipt: TxValidityReceipt::new(
                [1u8; 48],
                transaction_proof_digest(&proof),
                [2u8; 48],
                expected_profile,
            ),
            proof: Some(ProofEnvelope {
                kind: ProofArtifactKind::InlineTx,
                verifier_profile: expected_profile,
                artifact_bytes,
            }),
        };

        let err = tx_validity_claims_from_tx_artifacts(&[tx], &[artifact])
            .expect_err("claim derivation must reject malformed inline proof without panic");
        match err {
            ProofError::TransactionProofInputsMismatch { index, message } => {
                assert_eq!(index, 0);
                assert!(message.contains("transaction nullifier length"));
            }
            ProofError::TransactionProofVerification { index, message } => {
                assert_eq!(index, 0);
                assert!(message.contains("failed to decode inline tx proof artifact"));
            }
            other => panic!("unexpected malformed inline proof error: {other:?}"),
        }
    }

    fn fake_native_tx_leaf_record(seed: u8) -> NativeTxLeafRecord {
        NativeTxLeafRecord {
            params_fingerprint: [seed; 48],
            spec_digest: [seed; 32],
            relation_id: [seed; 32],
            shape_digest: [seed; 32],
            statement_digest: [seed; 48],
            commitment: superneo_backend_lattice::LatticeCommitment::digest_only([seed; 48]),
            proof_digest: [seed; 48],
        }
    }

    #[derive(Clone)]
    struct ReceiptRootCallerFixture {
        parent_tree: CommitmentTreeState,
        transactions: Vec<crate::types::Transaction>,
        tx_artifacts: Vec<TxValidityArtifact>,
        verified_records: Vec<VerifiedNativeTxLeaf>,
        backend_inputs: BlockBackendInputs,
        block: Block<TestHeader>,
        envelope: ProofEnvelope,
        statement_commitment: [u8; 48],
        metadata: crate::types::ReceiptRootMetadata,
    }

    struct NativeTxLeafCacheGuard;

    impl Drop for NativeTxLeafCacheGuard {
        fn drop(&mut self) {
            clear_verified_native_tx_leaf_store();
        }
    }

    fn receipt_root_caller_fixture() -> ReceiptRootCallerFixture {
        static FIXTURE: OnceLock<ReceiptRootCallerFixture> = OnceLock::new();
        FIXTURE
            .get_or_init(build_receipt_root_caller_fixture)
            .clone()
    }

    fn build_receipt_root_caller_fixture() -> ReceiptRootCallerFixture {
        let parent_tree = CommitmentTreeState::default();
        let tx = crate::types::Transaction::new_with_hashes(
            vec![[1u8; 48]],
            vec![[2u8; 48]],
            [3u8; 48],
            DEFAULT_VERSION_BINDING,
            vec![[4u8; 48]],
        );
        let transactions = vec![tx.clone()];
        let da_params = crate::types::DaParams {
            chunk_size: 1024,
            sample_count: 4,
        };
        let da_encoding =
            crate::types::encode_da_blob(&transactions, da_params).expect("fixture da blob");
        let da_root = da_encoding.root();
        let da_chunk_count =
            u32::try_from(da_encoding.chunks().len()).expect("fixture DA chunk count fits u32");
        let native_tx_profile = experimental_native_tx_leaf_verifier_profile();
        let receipt =
            TxValidityReceipt::new([0x11u8; 48], [0x12u8; 48], [0x13u8; 48], native_tx_profile);
        let tx_leaf_bytes = b"receipt-root caller native tx-leaf sentinel".to_vec();
        let tx_artifact = TxValidityArtifact {
            receipt: receipt.clone(),
            proof: Some(ProofEnvelope {
                kind: ProofArtifactKind::TxLeaf,
                verifier_profile: native_tx_profile,
                artifact_bytes: tx_leaf_bytes.clone(),
            }),
        };
        let binding = TxStatementBinding {
            statement_hash: receipt.statement_hash,
            anchor: parent_tree.root(),
            fee: 7,
            circuit_version: u32::from(DEFAULT_VERSION_BINDING.circuit),
        };
        let claim = TxValidityClaim::new(receipt.clone(), binding.clone());
        let statement_commitment =
            commitment_from_statement_bindings(std::slice::from_ref(&binding))
                .expect("fixture statement commitment");
        let updated_tree =
            apply_commitments(&parent_tree, &transactions).expect("fixture commitment tree update");
        let lists = commitment_nullifier_lists(&transactions).expect("fixture nullifier lists");
        let nullifier_root =
            nullifier_root_from_list(&lists.nullifiers).expect("fixture nullifier root");
        let commitment_proof = CommitmentBlockProver::new()
            .prove_from_statement_hashes_with_inputs(
                &[receipt.statement_hash],
                parent_tree.root(),
                updated_tree.root(),
                kernel_root_from_shielded_root(&parent_tree.root()),
                kernel_root_from_shielded_root(&updated_tree.root()),
                nullifier_root,
                da_root,
                lists.nullifiers,
                lists.sorted_nullifiers,
            )
            .expect("fixture commitment proof");

        let metadata = crate::types::ReceiptRootMetadata {
            params_fingerprint: [0x21u8; 48],
            relation_id: [0x22u8; 32],
            shape_digest: [0x23u8; 32],
            leaf_count: 1,
            fold_count: 0,
        };
        let root_proof = b"receipt-root backend sentinel proof".to_vec();
        let receipt_root_payload = crate::types::ReceiptRootProofPayload {
            root_proof: root_proof.clone(),
            metadata: metadata.clone(),
            receipts: vec![receipt.clone()],
        };
        let native_root_profile = experimental_native_receipt_root_verifier_profile();
        let block = Block {
            header: TestHeader {
                da_params,
                da_root,
                message_root: [0u8; 48],
            },
            transactions: transactions.clone(),
            coinbase: None,
            proven_batch: Some(crate::types::ProvenBatch {
                version: 2,
                tx_count: transactions.len() as u32,
                tx_statements_commitment: statement_commitment,
                da_root,
                da_chunk_count,
                commitment_proof,
                mode: ProvenBatchMode::ReceiptRoot,
                proof_kind: ProofArtifactKind::ReceiptRoot,
                verifier_profile: native_root_profile,
                receipt_root: Some(receipt_root_payload),
            }),
            block_artifact: None,
            tx_validity_claims: Some(vec![claim]),
            tx_statements_commitment: Some(statement_commitment),
            proof_verification_mode: ProofVerificationMode::SelfContainedAggregation,
        };
        let verified_record = VerifiedNativeTxLeaf {
            tx: tx_leaf_public_tx_from_consensus_tx(&tx),
            receipt: receipt.clone(),
            binding,
            leaf: fake_native_tx_leaf_record(7),
        };
        let tx_artifacts = vec![tx_artifact];
        ReceiptRootCallerFixture {
            parent_tree,
            transactions,
            tx_artifacts: tx_artifacts.clone(),
            verified_records: vec![verified_record],
            backend_inputs: BlockBackendInputs::from_tx_validity_artifacts(tx_artifacts),
            block,
            envelope: ProofEnvelope {
                kind: ProofArtifactKind::ReceiptRoot,
                verifier_profile: native_root_profile,
                artifact_bytes: root_proof,
            },
            statement_commitment,
            metadata,
        }
    }

    fn install_receipt_root_fixture_cache(
        fixture: &ReceiptRootCallerFixture,
    ) -> NativeTxLeafCacheGuard {
        clear_verified_native_tx_leaf_store();
        for (artifact, record) in fixture.tx_artifacts.iter().zip(&fixture.verified_records) {
            let artifact_bytes = &artifact
                .proof
                .as_ref()
                .expect("fixture tx artifact has proof")
                .artifact_bytes;
            NATIVE_TX_LEAF_VERIFY_CACHE
                .lock()
                .insert(native_tx_leaf_artifact_hash(artifact_bytes), record.clone());
        }
        NativeTxLeafCacheGuard
    }

    fn with_receipt_root_backend_override<T>(
        override_fn: ReceiptRootBackendOverride,
        body: impl FnOnce() -> T,
    ) -> T {
        RECEIPT_ROOT_BACKEND_OVERRIDE.with(|override_cell| {
            assert!(
                override_cell.borrow().is_none(),
                "nested receipt-root backend overrides are not supported"
            );
            *override_cell.borrow_mut() = Some(override_fn);
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        RECEIPT_ROOT_BACKEND_OVERRIDE.with(|override_cell| {
            *override_cell.borrow_mut() = None;
        });
        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn expect_receipt_root_backend_not_called<T>(
        body: impl FnOnce() -> Result<T, ProofError>,
    ) -> ProofError {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_override = Arc::clone(&calls);
        let err = with_receipt_root_backend_override(
            Arc::new(move |_, _, _| {
                calls_for_override.fetch_add(1, Ordering::SeqCst);
                Err(ProofError::AggregationProofVerification(
                    "sentinel receipt-root backend verifier was called".to_string(),
                ))
            }),
            || match body() {
                Ok(_) => panic!("caller-level receipt-root admission must reject"),
                Err(err) => err,
            },
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "receipt-root backend verifier was reached before caller-level rejection"
        );
        err
    }

    #[test]
    fn parallel_receipt_root_payload_mismatches_reject_before_backend() {
        let _guard = set_native_receipt_root_verify_mode("verified_records");
        let fixture = receipt_root_caller_fixture();
        let _cache_guard = install_receipt_root_fixture_cache(&fixture);

        let mut leaf_count_mismatch = fixture.block.clone();
        leaf_count_mismatch
            .proven_batch
            .as_mut()
            .expect("fixture proven batch")
            .receipt_root
            .as_mut()
            .expect("fixture receipt-root payload")
            .metadata
            .leaf_count += 1;
        let err = expect_receipt_root_backend_not_called(|| {
            ParallelProofVerifier::new().verify_block_with_backend(
                &leaf_count_mismatch,
                Some(&fixture.backend_inputs),
                &fixture.parent_tree,
            )
        });
        assert!(matches!(
            err,
            ProofError::ProvenBatchBindingMismatch(message)
                if message.contains("leaf_count mismatch")
        ));

        let mut block = fixture.block.clone();
        block
            .proven_batch
            .as_mut()
            .expect("fixture proven batch")
            .receipt_root
            .as_mut()
            .expect("fixture receipt-root payload")
            .receipts[0]
            .proof_digest[0] ^= 0x01;

        let err = expect_receipt_root_backend_not_called(|| {
            ParallelProofVerifier::new().verify_block_with_backend(
                &block,
                Some(&fixture.backend_inputs),
                &fixture.parent_tree,
            )
        });
        assert!(matches!(
            err,
            ProofError::ProvenBatchBindingMismatch(message)
                if message.contains("payload receipts do not match")
        ));
    }

    #[test]
    fn receipt_root_artifact_kind_and_profile_mismatch_reject_before_backend() {
        let _guard = set_native_receipt_root_verify_mode("verified_records");
        let fixture = receipt_root_caller_fixture();
        let verifier = ReceiptRootVerifier;

        let mut wrong_kind = fixture.envelope.clone();
        wrong_kind.kind = ProofArtifactKind::TxLeaf;
        let err = expect_receipt_root_backend_not_called(|| {
            verifier.verify_block_artifact(
                &fixture.transactions,
                Some(&fixture.tx_artifacts),
                &fixture.statement_commitment,
                &wrong_kind,
            )
        });
        assert!(matches!(
            err,
            ProofError::UnsupportedProofArtifact(message)
                if message.contains("expected receipt_root block artifact, got tx_leaf")
        ));

        let mut wrong_profile = fixture.envelope.clone();
        wrong_profile.verifier_profile = experimental_native_tx_leaf_verifier_profile();
        let err = expect_receipt_root_backend_not_called(|| {
            verifier.verify_block_artifact(
                &fixture.transactions,
                Some(&fixture.tx_artifacts),
                &fixture.statement_commitment,
                &wrong_profile,
            )
        });
        assert!(matches!(
            err,
            ProofError::AggregationProofInputsMismatch(message)
                if message.contains("receipt-root requires the native verifier profile")
        ));
    }

    #[test]
    fn receipt_root_statement_commitment_mismatch_rejects_before_backend() {
        let _guard = set_native_receipt_root_verify_mode("verified_records");
        let fixture = receipt_root_caller_fixture();
        let _cache_guard = install_receipt_root_fixture_cache(&fixture);
        let mut wrong_commitment = fixture.statement_commitment;
        wrong_commitment[0] ^= 0x01;

        let err = expect_receipt_root_backend_not_called(|| {
            ReceiptRootVerifier.verify_block_artifact(
                &fixture.transactions,
                Some(&fixture.tx_artifacts),
                &wrong_commitment,
                &fixture.envelope,
            )
        });
        assert!(matches!(
            err,
            ProofError::AggregationProofInputsMismatch(message)
                if message.contains("statement commitment mismatch")
        ));
    }

    #[test]
    fn parallel_receipt_root_verified_metadata_leaf_count_mismatch_rejects() {
        let _guard = set_native_receipt_root_verify_mode("verified_records");
        let fixture = receipt_root_caller_fixture();
        let _cache_guard = install_receipt_root_fixture_cache(&fixture);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_override = Arc::clone(&calls);
        let mut wrong_metadata = fixture.metadata.clone();
        wrong_metadata.leaf_count = 2;
        let expected_artifact_bytes = fixture.envelope.artifact_bytes.clone();

        let err = with_receipt_root_backend_override(
            Arc::new(move |records, artifacts, artifact_bytes| {
                calls_for_override.fetch_add(1, Ordering::SeqCst);
                assert_eq!(records.len(), 1);
                assert_eq!(artifacts.len(), 1);
                assert_eq!(artifact_bytes, expected_artifact_bytes.as_slice());
                Ok(wrong_metadata.clone())
            }),
            || {
                ParallelProofVerifier::new()
                    .verify_block_with_backend(
                        &fixture.block,
                        Some(&fixture.backend_inputs),
                        &fixture.parent_tree,
                    )
                    .expect_err("verified metadata leaf-count mismatch must reject")
            },
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "metadata mismatch test must reach the root backend exactly once"
        );
        assert!(matches!(
            err,
            ProofError::AggregationProofInputsMismatch(message)
                if message.contains("verified leaf count mismatch")
        ));
    }

    #[test]
    fn native_tx_leaf_cache_hit_requires_same_transaction_view() {
        clear_verified_native_tx_leaf_store();
        let native_profile = experimental_native_tx_leaf_verifier_profile();
        let original_tx = tx_with_commitments(vec![[1u8; 48]]);
        let mut mutated_tx = original_tx.clone();
        mutated_tx.commitments[0] = [2u8; 48];

        let receipt = TxValidityReceipt::new([3u8; 48], [4u8; 48], [5u8; 48], native_profile);
        let artifact_bytes = b"cached native tx leaf artifact placeholder".to_vec();
        let artifact = TxValidityArtifact {
            receipt: receipt.clone(),
            proof: Some(ProofEnvelope {
                kind: ProofArtifactKind::TxLeaf,
                verifier_profile: native_profile,
                artifact_bytes: artifact_bytes.clone(),
            }),
        };

        let cached = VerifiedNativeTxLeaf {
            tx: tx_leaf_public_tx_from_consensus_tx(&original_tx),
            receipt: receipt.clone(),
            binding: TxStatementBinding {
                statement_hash: receipt.statement_hash,
                anchor: [6u8; 48],
                fee: 0,
                circuit_version: u32::from(original_tx.version.circuit),
            },
            leaf: fake_native_tx_leaf_record(7),
        };
        NATIVE_TX_LEAF_VERIFY_CACHE
            .lock()
            .insert(native_tx_leaf_artifact_hash(&artifact_bytes), cached);

        let err = verify_native_tx_leaf_artifact_record(&mutated_tx, &artifact, None)
            .expect_err("cache hit for a different transaction view must reject");
        match err {
            ProofError::TransactionProofInputsMismatch { message, .. } => {
                assert!(message.contains("transaction mismatch"));
            }
            other => panic!("unexpected cache mismatch error: {other:?}"),
        }
        clear_verified_native_tx_leaf_store();
    }

    #[test]
    fn verifier_panic_is_captured() {
        let err = run_verifier(
            "test verifier".to_string(),
            || -> Result<(), &'static str> { panic!("boom") },
            |_| unreachable!("panic path should bypass the error mapper"),
        )
        .expect_err("panic should be captured");
        assert!(
            matches!(err, ProofError::VerifierPanicked(message) if message.contains("test verifier") && message.contains("boom"))
        );
    }

    #[test]
    fn native_receipt_root_verify_mode_defaults_to_verified_records() {
        let _guard = set_native_receipt_root_verify_mode("");
        assert_eq!(
            load_native_receipt_root_verify_mode(),
            NativeReceiptRootVerifyMode::VerifiedRecords
        );
        assert_eq!(native_receipt_root_verify_mode_label(), "verified_records");
    }

    #[test]
    fn native_receipt_root_verify_mode_accepts_replay() {
        let _guard = set_native_receipt_root_verify_mode("replay");
        assert_eq!(
            load_native_receipt_root_verify_mode(),
            NativeReceiptRootVerifyMode::Replay
        );
    }

    #[test]
    fn native_receipt_root_verify_mode_accepts_cross_check_aliases() {
        let _guard = set_native_receipt_root_verify_mode("cross-check");
        assert_eq!(
            load_native_receipt_root_verify_mode(),
            NativeReceiptRootVerifyMode::CrossCheck
        );
    }

    fn sample_recursive_records(tx_count: u32) -> Vec<crate::backend_interface::BlockLeafRecordV1> {
        (0..tx_count)
            .map(|tx_index| crate::backend_interface::BlockLeafRecordV1 {
                tx_index,
                receipt_statement_hash: [0x10u8.wrapping_add(tx_index as u8); 48],
                receipt_proof_digest: [0x20u8.wrapping_add(tx_index as u8); 48],
                receipt_public_inputs_digest: [0x30u8.wrapping_add(tx_index as u8); 48],
                receipt_verifier_profile: [0x40u8.wrapping_add(tx_index as u8); 48],
                leaf_params_fingerprint: [0x50u8.wrapping_add(tx_index as u8); 48],
                leaf_spec_digest: [0x60u8.wrapping_add(tx_index as u8); 32],
                leaf_relation_id: [0x70u8.wrapping_add(tx_index as u8); 32],
                leaf_shape_digest: [0x80u8.wrapping_add(tx_index as u8); 32],
                leaf_statement_digest: [0x90u8.wrapping_add(tx_index as u8); 48],
                leaf_commitment_digest: [0xa0u8.wrapping_add(tx_index as u8); 48],
                leaf_proof_digest: [0xb0u8.wrapping_add(tx_index as u8); 48],
            })
            .collect::<Vec<_>>()
    }

    fn sample_recursive_semantic() -> crate::backend_interface::BlockSemanticInputsV1 {
        crate::backend_interface::BlockSemanticInputsV1 {
            tx_statements_commitment: [0u8; 48],
            start_shielded_root: [3u8; 48],
            end_shielded_root: [4u8; 48],
            start_kernel_root: [5u8; 48],
            end_kernel_root: [6u8; 48],
            nullifier_root: [7u8; 48],
            da_root: [8u8; 48],
            message_root: [11u8; 48],
            start_tree_commitment: [9u8; 48],
            end_tree_commitment: [10u8; 48],
        }
    }

    fn sample_recursive_block_artifact_v1(
        tx_count: u32,
    ) -> crate::backend_interface::RecursiveBlockArtifactV1 {
        let records = sample_recursive_records(tx_count);
        let semantic = sample_recursive_semantic();
        crate::backend_interface::prove_block_recursive_v1(
            &crate::backend_interface::BlockRecursiveProverInputV1 { records, semantic },
        )
        .expect("prove recursive_block_v1 artifact")
    }

    fn sample_recursive_block_artifact_v2(
        tx_count: u32,
    ) -> crate::backend_interface::RecursiveBlockArtifactV2 {
        let records = sample_recursive_records(tx_count);
        let semantic = sample_recursive_semantic();
        crate::backend_interface::prove_block_recursive_v2(
            &crate::backend_interface::BlockRecursiveProverInputV2 { records, semantic },
        )
        .expect("prove recursive_block_v2 artifact")
    }

    fn oversized_recursive_block_envelope(kind: ProofArtifactKind) -> ProofEnvelope {
        let (verifier_profile, max_len) = match kind {
            ProofArtifactKind::RecursiveBlockV1 => (
                backend_recursive_block_profile_v1(),
                RECURSIVE_BLOCK_V1_ARTIFACT_MAX_BYTES,
            ),
            ProofArtifactKind::RecursiveBlockV2 => (
                backend_recursive_block_profile_v2(),
                RECURSIVE_BLOCK_V2_ARTIFACT_MAX_BYTES,
            ),
            other => panic!("unexpected recursive block kind {}", other.label()),
        };
        ProofEnvelope {
            kind,
            verifier_profile,
            artifact_bytes: vec![0xa5; max_len + 1],
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RecursiveBlockV1OracleSummary {
        header_version: u32,
        tx_count: u32,
        tx_statements_commitment: [u8; 48],
    }

    fn put_recursive_v1_oracle_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn put_recursive_v1_oracle_digest32(out: &mut Vec<u8>, seed: u8) {
        out.extend_from_slice(&[seed; 32]);
    }

    fn put_recursive_v1_oracle_digest48(out: &mut Vec<u8>, seed: u8) {
        out.extend_from_slice(&[seed; 48]);
    }

    fn synthetic_recursive_block_v1_artifact_bytes(
        tx_count: u32,
        tx_statements_commitment: [u8; 48],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECURSIVE_BLOCK_V1_ARTIFACT_MAX_BYTES);
        put_recursive_v1_oracle_u32(&mut out, RECURSIVE_BLOCK_ARTIFACT_VERSION_V1);
        put_recursive_v1_oracle_digest32(&mut out, 0x11);
        put_recursive_v1_oracle_u32(&mut out, 1);
        put_recursive_v1_oracle_u32(&mut out, 1);
        for seed in 0x21..=0x28 {
            put_recursive_v1_oracle_digest32(&mut out, seed);
        }
        put_recursive_v1_oracle_u32(
            &mut out,
            block_recursion::RECURSIVE_BLOCK_PROOF_BYTES_V1 as u32,
        );
        put_recursive_v1_oracle_digest32(&mut out, 0x31);
        assert_eq!(out.len(), block_recursion::RECURSIVE_BLOCK_HEADER_BYTES_V1);

        out.extend(std::iter::repeat_n(
            0x42,
            block_recursion::RECURSIVE_BLOCK_PROOF_BYTES_V1,
        ));

        put_recursive_v1_oracle_u32(&mut out, tx_count);
        out.extend_from_slice(&tx_statements_commitment);
        for seed in 0x51..=0x5b {
            put_recursive_v1_oracle_digest48(&mut out, seed);
        }
        assert_eq!(out.len(), RECURSIVE_BLOCK_V1_ARTIFACT_MAX_BYTES);
        out
    }

    fn recursive_v1_oracle_read<const N: usize>(
        bytes: &[u8],
        cursor: &mut usize,
    ) -> Option<[u8; N]> {
        let end = cursor.checked_add(N)?;
        let slice = bytes.get(*cursor..end)?;
        *cursor = end;
        slice.try_into().ok()
    }

    fn recursive_v1_oracle_read_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
        Some(u32::from_le_bytes(recursive_v1_oracle_read::<4>(
            bytes, cursor,
        )?))
    }

    fn recursive_block_v1_parse_oracle(bytes: &[u8]) -> Option<RecursiveBlockV1OracleSummary> {
        let minimum_len = block_recursion::RECURSIVE_BLOCK_HEADER_BYTES_V1
            + block_recursion::RECURSIVE_BLOCK_PUBLIC_BYTES_V1;
        if bytes.len() < minimum_len {
            return None;
        }

        let mut cursor = 0usize;
        let header_version = recursive_v1_oracle_read_u32(bytes, &mut cursor)?;
        let _tx_line_digest = recursive_v1_oracle_read::<32>(bytes, &mut cursor)?;
        let profile_tag = recursive_v1_oracle_read_u32(bytes, &mut cursor)?;
        if profile_tag != 1 && profile_tag != 2 {
            return None;
        }
        let relation_kind = recursive_v1_oracle_read_u32(bytes, &mut cursor)?;
        if !(1..=3).contains(&relation_kind) {
            return None;
        }
        for _ in 0..8 {
            let _digest = recursive_v1_oracle_read::<32>(bytes, &mut cursor)?;
        }
        let proof_bytes = recursive_v1_oracle_read_u32(bytes, &mut cursor)? as usize;
        if proof_bytes != block_recursion::RECURSIVE_BLOCK_PROOF_BYTES_V1 {
            return None;
        }
        let _statement_digest = recursive_v1_oracle_read::<32>(bytes, &mut cursor)?;
        if cursor != block_recursion::RECURSIVE_BLOCK_HEADER_BYTES_V1 {
            return None;
        }

        let proof_end = cursor.checked_add(proof_bytes)?;
        let public_end = proof_end.checked_add(block_recursion::RECURSIVE_BLOCK_PUBLIC_BYTES_V1)?;
        if public_end > bytes.len() {
            return None;
        }
        cursor = proof_end;
        let tx_count = recursive_v1_oracle_read_u32(bytes, &mut cursor)?;
        let tx_statements_commitment = recursive_v1_oracle_read::<48>(bytes, &mut cursor)?;
        for _ in 0..11 {
            let _digest = recursive_v1_oracle_read::<48>(bytes, &mut cursor)?;
        }
        if cursor != bytes.len() {
            return None;
        }

        Some(RecursiveBlockV1OracleSummary {
            header_version,
            tx_count,
            tx_statements_commitment,
        })
    }

    fn recursive_block_v1_oracle_admission_label(
        envelope: &ProofEnvelope,
        expected_tx_count: usize,
        expected_commitment: &[u8; 48],
    ) -> Option<&'static str> {
        if envelope.kind != ProofArtifactKind::RecursiveBlockV1 {
            return Some("artifact_kind_mismatch");
        }
        if envelope.verifier_profile != backend_recursive_block_profile_v1() {
            return Some("verifier_profile_mismatch");
        }
        if envelope.artifact_bytes.len() > RECURSIVE_BLOCK_V1_ARTIFACT_MAX_BYTES {
            return Some("artifact_too_large");
        }
        let Some(parsed) = recursive_block_v1_parse_oracle(&envelope.artifact_bytes) else {
            return Some("artifact_decode_failed");
        };
        if parsed.header_version != RECURSIVE_BLOCK_ARTIFACT_VERSION_V1 {
            return Some("header_version_mismatch");
        }
        if parsed.tx_count as usize != expected_tx_count {
            return Some("tx_count_mismatch");
        }
        if parsed.tx_statements_commitment != *expected_commitment {
            return Some("statement_commitment_mismatch");
        }
        None
    }

    fn recursive_block_v1_production_admission_label(
        envelope: &ProofEnvelope,
        expected_tx_count: usize,
        expected_commitment: &[u8; 48],
    ) -> Option<&'static str> {
        let admission = recursive_block_admission_input_for_predecode(
            ProofArtifactKind::RecursiveBlockV1,
            envelope,
            envelope.verifier_profile == backend_recursive_block_profile_v1(),
        );
        if let Err(rejection) = evaluate_recursive_block_artifact_admission(admission) {
            return Some(rejection.label());
        }
        let parsed = match deserialize_recursive_block_artifact_v1(&envelope.artifact_bytes) {
            Ok(parsed) => parsed,
            Err(_) => {
                let rejection = evaluate_recursive_block_artifact_admission(
                    recursive_block_decode_admission_input(admission),
                )
                .expect_err("failed recursive-block decode must reject");
                return Some(rejection.label());
            }
        };
        let decoded = RecursiveBlockArtifactAdmissionInput {
            header_version_matches: parsed.artifact.header.artifact_version_rec
                == RECURSIVE_BLOCK_ARTIFACT_VERSION_V1,
            tx_count_matches: parsed.public.tx_count as usize == expected_tx_count,
            statement_commitment_matches: parsed.public.tx_statements_commitment
                == *expected_commitment,
            public_replay_matches: true,
            ..admission
        };
        evaluate_recursive_block_artifact_admission(decoded)
            .err()
            .map(RecursiveBlockArtifactAdmissionRejection::label)
    }

    #[test]
    fn recursive_block_v1_fixed_wire_cap_and_parser_match_oracle() {
        assert_eq!(
            RECURSIVE_BLOCK_V1_ARTIFACT_MAX_BYTES,
            block_recursion::RECURSIVE_BLOCK_HEADER_BYTES_V1
                + block_recursion::RECURSIVE_BLOCK_PROOF_BYTES_V1
                + block_recursion::RECURSIVE_BLOCK_PUBLIC_BYTES_V1,
            "consensus pre-decode cap must match the fixed v1 serializer width"
        );

        let expected_commitment = [0x33u8; 48];
        let valid = synthetic_recursive_block_v1_artifact_bytes(2, expected_commitment);
        assert_eq!(valid.len(), RECURSIVE_BLOCK_V1_ARTIFACT_MAX_BYTES);

        const PROFILE_TAG_OFFSET: usize = 36;
        const RELATION_KIND_OFFSET: usize = 40;
        const PROOF_BYTES_OFFSET: usize = 300;
        let public_offset = block_recursion::RECURSIVE_BLOCK_HEADER_BYTES_V1
            + block_recursion::RECURSIVE_BLOCK_PROOF_BYTES_V1;
        let tx_count_offset = public_offset;
        let tx_commitment_offset = public_offset + 4;

        let mut corpus = vec![
            (
                "valid",
                ProofEnvelope {
                    kind: ProofArtifactKind::RecursiveBlockV1,
                    verifier_profile: backend_recursive_block_profile_v1(),
                    artifact_bytes: valid.clone(),
                },
            ),
            (
                "wrong-kind-precedes-decode",
                ProofEnvelope {
                    kind: ProofArtifactKind::ReceiptRoot,
                    verifier_profile: backend_recursive_block_profile_v1(),
                    artifact_bytes: Vec::new(),
                },
            ),
            (
                "profile-mismatch-precedes-decode",
                ProofEnvelope {
                    kind: ProofArtifactKind::RecursiveBlockV1,
                    verifier_profile: [0x99; 48],
                    artifact_bytes: Vec::new(),
                },
            ),
        ];

        let mut oversized = valid.clone();
        oversized.push(0);
        corpus.push((
            "oversized-precedes-trailing-decode",
            ProofEnvelope {
                kind: ProofArtifactKind::RecursiveBlockV1,
                verifier_profile: backend_recursive_block_profile_v1(),
                artifact_bytes: oversized,
            },
        ));

        for (name, bytes) in [
            ("empty-decode-failed", Vec::new()),
            (
                "minimum-without-proof-decode-failed",
                valid[..block_recursion::RECURSIVE_BLOCK_HEADER_BYTES_V1
                    + block_recursion::RECURSIVE_BLOCK_PUBLIC_BYTES_V1]
                    .to_vec(),
            ),
            ("truncated-decode-failed", valid[..valid.len() - 1].to_vec()),
        ] {
            corpus.push((
                name,
                ProofEnvelope {
                    kind: ProofArtifactKind::RecursiveBlockV1,
                    verifier_profile: backend_recursive_block_profile_v1(),
                    artifact_bytes: bytes,
                },
            ));
        }

        let mut bad_profile_tag = valid.clone();
        bad_profile_tag[PROFILE_TAG_OFFSET..PROFILE_TAG_OFFSET + 4]
            .copy_from_slice(&9u32.to_le_bytes());
        corpus.push((
            "bad-profile-tag-decode-failed",
            ProofEnvelope {
                kind: ProofArtifactKind::RecursiveBlockV1,
                verifier_profile: backend_recursive_block_profile_v1(),
                artifact_bytes: bad_profile_tag,
            },
        ));

        let mut bad_relation_kind = valid.clone();
        bad_relation_kind[RELATION_KIND_OFFSET..RELATION_KIND_OFFSET + 4]
            .copy_from_slice(&8u32.to_le_bytes());
        corpus.push((
            "bad-relation-kind-decode-failed",
            ProofEnvelope {
                kind: ProofArtifactKind::RecursiveBlockV1,
                verifier_profile: backend_recursive_block_profile_v1(),
                artifact_bytes: bad_relation_kind,
            },
        ));

        let mut bad_proof_len = valid.clone();
        bad_proof_len[PROOF_BYTES_OFFSET..PROOF_BYTES_OFFSET + 4].copy_from_slice(
            &(block_recursion::RECURSIVE_BLOCK_PROOF_BYTES_V1 as u32 + 1).to_le_bytes(),
        );
        corpus.push((
            "bad-proof-len-decode-failed",
            ProofEnvelope {
                kind: ProofArtifactKind::RecursiveBlockV1,
                verifier_profile: backend_recursive_block_profile_v1(),
                artifact_bytes: bad_proof_len,
            },
        ));

        let mut bad_header_version = valid.clone();
        bad_header_version[0..4]
            .copy_from_slice(&(RECURSIVE_BLOCK_ARTIFACT_VERSION_V1 + 1).to_le_bytes());
        corpus.push((
            "header-version-mismatch",
            ProofEnvelope {
                kind: ProofArtifactKind::RecursiveBlockV1,
                verifier_profile: backend_recursive_block_profile_v1(),
                artifact_bytes: bad_header_version,
            },
        ));

        let mut tx_count_mismatch = valid.clone();
        tx_count_mismatch[tx_count_offset..tx_count_offset + 4]
            .copy_from_slice(&3u32.to_le_bytes());
        corpus.push((
            "tx-count-mismatch",
            ProofEnvelope {
                kind: ProofArtifactKind::RecursiveBlockV1,
                verifier_profile: backend_recursive_block_profile_v1(),
                artifact_bytes: tx_count_mismatch,
            },
        ));

        let mut commitment_mismatch = valid.clone();
        commitment_mismatch[tx_commitment_offset] ^= 0x5a;
        corpus.push((
            "statement-commitment-mismatch",
            ProofEnvelope {
                kind: ProofArtifactKind::RecursiveBlockV1,
                verifier_profile: backend_recursive_block_profile_v1(),
                artifact_bytes: commitment_mismatch,
            },
        ));

        for (name, envelope) in corpus {
            let expected =
                recursive_block_v1_oracle_admission_label(&envelope, 2, &expected_commitment);
            let actual =
                recursive_block_v1_production_admission_label(&envelope, 2, &expected_commitment);
            assert_eq!(
                actual, expected,
                "{name}: recursive_block_v1 production admission drifted from byte oracle"
            );
        }
    }

    #[test]
    fn recursive_block_v1_artifact_rejects_oversized_bytes_before_deserialize() {
        let envelope = oversized_recursive_block_envelope(ProofArtifactKind::RecursiveBlockV1);
        let admission = recursive_block_admission_input_for_predecode(
            ProofArtifactKind::RecursiveBlockV1,
            &envelope,
            envelope.verifier_profile == backend_recursive_block_profile_v1(),
        );
        let err = evaluate_recursive_block_artifact_admission(
            recursive_block_decode_admission_input(admission),
        )
        .expect_err("oversized recursive_block_v1 must reject before decode");
        assert_eq!(err.label(), "artifact_too_large");
    }

    #[test]
    fn recursive_block_v2_artifact_rejects_oversized_bytes_before_deserialize() {
        let envelope = oversized_recursive_block_envelope(ProofArtifactKind::RecursiveBlockV2);
        let admission = recursive_block_admission_input_for_predecode(
            ProofArtifactKind::RecursiveBlockV2,
            &envelope,
            envelope.verifier_profile == backend_recursive_block_profile_v2(),
        );
        let err = evaluate_recursive_block_artifact_admission(
            recursive_block_decode_admission_input(admission),
        )
        .expect_err("oversized recursive_block_v2 must reject before decode");
        assert_eq!(err.label(), "artifact_too_large");
    }

    #[test]
    fn recursive_block_v2_registry_direct_verifier_requires_semantic_replay() {
        let registry = VerifierRegistry::default();
        let verifier_profile = backend_recursive_block_profile_v2();
        let verifier = registry
            .resolve(ProofArtifactKind::RecursiveBlockV2, verifier_profile)
            .expect("recursive_block_v2 verifier registered");
        let artifact = sample_recursive_block_artifact_v2(1);
        let bytes = crate::backend_interface::serialize_recursive_block_artifact_v2(&artifact)
            .expect("serialize recursive_block_v2 artifact");
        let envelope = ProofEnvelope {
            kind: ProofArtifactKind::RecursiveBlockV2,
            verifier_profile,
            artifact_bytes: bytes,
        };
        let err = verifier
            .verify_block_artifact(&[tx_with_commitments(vec![])], None, &[0u8; 48], &envelope)
            .expect_err("registry recursive_block_v2 verifier must require semantic replay");
        assert_eq!(
            recursive_block_direct_verifier_error_label(&err),
            "requires_semantic_replay"
        );
    }

    #[test]
    fn recursive_block_v1_registry_direct_verifier_requires_semantic_replay() {
        let registry = VerifierRegistry::default();
        let verifier_profile = backend_recursive_block_profile_v1();
        let verifier = registry
            .resolve(ProofArtifactKind::RecursiveBlockV1, verifier_profile)
            .expect("recursive_block_v1 verifier registered");
        let artifact = sample_recursive_block_artifact_v1(1);
        let bytes = crate::backend_interface::serialize_recursive_block_artifact_v1(&artifact)
            .expect("serialize recursive_block_v1 artifact");
        let envelope = ProofEnvelope {
            kind: ProofArtifactKind::RecursiveBlockV1,
            verifier_profile,
            artifact_bytes: bytes,
        };
        let err = verifier
            .verify_block_artifact(&[tx_with_commitments(vec![])], None, &[0u8; 48], &envelope)
            .expect_err("registry recursive_block_v1 verifier must require semantic replay");
        assert_eq!(
            recursive_block_direct_verifier_error_label(&err),
            "requires_semantic_replay"
        );
    }

    #[test]
    fn recursive_block_v1_direct_verifier_requires_semantic_replay_before_tx_count_mismatch() {
        let verifier = RecursiveBlockVerifier {
            kind: ProofArtifactKind::RecursiveBlockV1,
        };
        let artifact = sample_recursive_block_artifact_v1(1);
        let bytes = crate::backend_interface::serialize_recursive_block_artifact_v1(&artifact)
            .expect("serialize recursive artifact");
        let envelope = ProofEnvelope {
            kind: ProofArtifactKind::RecursiveBlockV1,
            verifier_profile: backend_recursive_block_profile_v1(),
            artifact_bytes: bytes,
        };
        let err = verifier
            .verify_block_artifact(&[], None, &[0u8; 48], &envelope)
            .expect_err("direct recursive_block_v1 verifier must require semantic replay");
        assert_eq!(
            recursive_block_direct_verifier_error_label(&err),
            "requires_semantic_replay"
        );
    }

    #[test]
    fn recursive_block_v2_direct_verifier_requires_semantic_replay_before_tx_count_mismatch() {
        let verifier = RecursiveBlockVerifier {
            kind: ProofArtifactKind::RecursiveBlockV2,
        };
        let artifact = sample_recursive_block_artifact_v2(1);
        let bytes = crate::backend_interface::serialize_recursive_block_artifact_v2(&artifact)
            .expect("serialize recursive_block_v2 artifact");
        let envelope = ProofEnvelope {
            kind: ProofArtifactKind::RecursiveBlockV2,
            verifier_profile: backend_recursive_block_profile_v2(),
            artifact_bytes: bytes,
        };
        let err = verifier
            .verify_block_artifact(&[], None, &[0u8; 48], &envelope)
            .expect_err("direct recursive_block_v2 verifier must require semantic replay");
        assert_eq!(
            recursive_block_direct_verifier_error_label(&err),
            "requires_semantic_replay"
        );
    }
}
