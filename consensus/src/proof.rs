use crate::aggregation::{
    aggregation_proof_uncompressed_len, verify_aggregation_proof_with_metrics,
    warm_aggregation_cache_from_proof_bytes,
};
use crate::batch_proof::{
    FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK, FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST,
    decode_flat_batch_proof_bytes,
};
use crate::commitment_tree::CommitmentTreeState;
use crate::error::ProofError;
use crate::merge_root_layout::{
    merge_root_leaf_fan_in_from_env, merge_root_leaf_manifest_commitment,
    merge_root_tree_levels_for_tx_count,
};
use crate::receipt_arc_whir::{
    ReceiptArcWhirResidualReport, ReceiptArcWhirVerifyDetails,
    build_receipt_arc_whir_artifact_from_receipts,
    experimental_receipt_arc_whir_artifact_kind as receipt_arc_whir_kind,
    experimental_receipt_arc_whir_verifier_profile as receipt_arc_whir_profile,
    receipt_arc_whir_metadata, verify_receipt_arc_whir_artifact_from_receipts,
};
use crate::types::{
    Block, DaParams, DaRoot, FeeCommitment, ProofArtifactKind, ProofEnvelope,
    ProofVerificationMode, ProvenBatchMode, ReceiptRootMetadata, StarkCommitment, StateRoot,
    TxStatementBinding, TxValidityArtifact, TxValidityReceipt, VerifierProfileDigest,
    VersionCommitment, compute_fee_commitment, compute_proof_commitment,
    compute_version_commitment, da_root, kernel_root_from_shielded_root,
    legacy_block_artifact_verifier_profile,
};
use batch_circuit::{BatchPublicInputs, verify_batch_proof_bytes};
use block_circuit::{CommitmentBlockProof, CommitmentBlockProver, verify_block_commitment};
use crypto::hashes::blake3_384;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use parking_lot::Mutex;
use rayon::prelude::*;
use std::any::Any;
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use superneo_hegemon::{
    CanonicalTxValidityReceipt, NativeTxLeafRecord, TxLeafPublicTx,
    build_native_tx_leaf_receipt_root_artifact_bytes, build_receipt_root_artifact_bytes,
    build_tx_leaf_artifact_bytes, build_verified_tx_proof_receipt_root_artifact_bytes,
    decode_native_tx_leaf_artifact_bytes,
    experimental_native_receipt_root_verifier_profile as native_receipt_root_profile,
    experimental_native_tx_leaf_verifier_profile as native_tx_leaf_profile,
    max_native_receipt_root_artifact_bytes, max_native_tx_leaf_artifact_bytes,
    native_tx_leaf_record_from_artifact, verify_native_tx_leaf_artifact_bytes,
    verify_native_tx_leaf_receipt_root_artifact_bytes,
    verify_native_tx_leaf_receipt_root_artifact_from_records, verify_receipt_root_artifact_bytes,
    verify_tx_leaf_artifact_bytes, verify_verified_tx_proof_receipt_root_artifact_bytes,
};
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::{Felt, ciphertext_hash_bytes, felts_to_bytes48};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::proof::{
    SerializedStarkInputs, TransactionProof, transaction_proof_digest,
    transaction_public_inputs_digest, transaction_public_inputs_digest_from_serialized,
    transaction_statement_hash, transaction_verifier_profile_digest,
    transaction_verifier_profile_digest_for_version, verify as verify_transaction_proof,
};
#[cfg(test)]
use tx_proof_manifest::TxProofManifestPublicInputs;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExperimentalReceiptRootArtifact {
    pub artifact_bytes: Vec<u8>,
    pub metadata: ReceiptRootMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentNullifierLists {
    pub nullifiers: Vec<[u8; 48]>,
    pub sorted_nullifiers: Vec<[u8; 48]>,
}

const DEFAULT_NATIVE_TX_LEAF_VERIFY_CACHE_CAPACITY: usize = 4096;
const RECEIPT_ACCUMULATION_ARTIFACT_VERSION: u16 = 1;
const RECEIPT_ACCUMULATION_ARTIFACT_KIND_BYTES: [u8; 16] = *b"rcpt_accum_v0001";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ReceiptArcWhirExecutionTrace {
    replayed_leaf_verifications: usize,
    used_old_aggregation_backend: bool,
}

thread_local! {
    static RECEIPT_ARC_WHIR_EXECUTION_TRACE: RefCell<Option<ReceiptArcWhirExecutionTrace>> =
        const { RefCell::new(None) };
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedNativeTxLeaf {
    receipt: TxValidityReceipt,
    binding: TxStatementBinding,
    leaf: NativeTxLeafRecord,
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

fn with_receipt_arc_whir_execution_trace<T>(
    f: impl FnOnce() -> Result<T, ProofError>,
) -> Result<(T, ReceiptArcWhirExecutionTrace), ProofError> {
    RECEIPT_ARC_WHIR_EXECUTION_TRACE.with(|trace| {
        let previous = trace.replace(Some(ReceiptArcWhirExecutionTrace::default()));
        let result = f();
        let current = trace
            .replace(previous)
            .expect("receipt_arc_whir execution trace must be present");
        result.map(|value| (value, current))
    })
}

fn note_receipt_arc_whir_leaf_verification() {
    RECEIPT_ARC_WHIR_EXECUTION_TRACE.with(|trace| {
        if let Some(current) = trace.borrow_mut().as_mut() {
            current.replayed_leaf_verifications += 1;
        }
    });
}

fn note_receipt_arc_whir_old_aggregation_backend() {
    RECEIPT_ARC_WHIR_EXECUTION_TRACE.with(|trace| {
        if let Some(current) = trace.borrow_mut().as_mut() {
            current.used_old_aggregation_backend = true;
        }
    });
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiptAccumulationArtifact {
    root_artifact_bytes: Vec<u8>,
    artifact_hashes: Vec<[u8; 48]>,
}

pub trait ReceiptAccumulator: Send + Sync {
    fn kind(&self) -> ProofArtifactKind;
    fn verifier_profile(&self) -> VerifierProfileDigest;
    fn build(
        &self,
        receipts: &[TxValidityReceipt],
        artifacts: &[TxValidityArtifact],
    ) -> Result<ProofEnvelope, ProofError>;
    fn verify(
        &self,
        receipts: &[TxValidityReceipt],
        expected_commitment: &[u8; 48],
        envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError>;
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
        registry.register(Arc::new(MergeRootP3Verifier));
        registry.register(Arc::new(ReceiptRootVerifier));
        registry.register(Arc::new(ReceiptArcWhirVerifier));
        registry.register(Arc::new(ReceiptAccumulationVerifier));
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
    let envelope = artifact
        .proof
        .as_ref()
        .ok_or(ProofError::MissingTransactionProofs)?;
    if envelope.kind != ProofArtifactKind::TxLeaf {
        return Err(ProofError::UnsupportedProofArtifact(format!(
            "expected tx_leaf proof envelope, got {}",
            envelope.kind.label()
        )));
    }
    if envelope.verifier_profile != experimental_native_tx_leaf_verifier_profile() {
        return Err(ProofError::TransactionProofInputsMismatch {
            index: 0,
            message: "native tx-leaf verifier profile mismatch".to_string(),
        });
    }
    if envelope.artifact_bytes.len() > max_native_tx_leaf_artifact_bytes() {
        return Err(ProofError::TransactionProofInputsMismatch {
            index: 0,
            message: format!(
                "native tx-leaf artifact size {} exceeds {}",
                envelope.artifact_bytes.len(),
                max_native_tx_leaf_artifact_bytes()
            ),
        });
    }
    if artifact.receipt.verifier_profile != experimental_native_tx_leaf_verifier_profile() {
        return Err(ProofError::TransactionProofInputsMismatch {
            index: 0,
            message: "native tx-leaf receipt verifier profile mismatch".to_string(),
        });
    }

    let artifact_hash = native_tx_leaf_artifact_hash(&envelope.artifact_bytes);
    if let Some(expected_hash) = expected_hash
        && expected_hash != artifact_hash
    {
        return Err(ProofError::AggregationProofInputsMismatch(
            "receipt accumulation artifact hash mismatch".to_string(),
        ));
    }
    if let Some(record) = NATIVE_TX_LEAF_VERIFY_CACHE.lock().get(artifact_hash) {
        if record.receipt == artifact.receipt {
            return Ok(record);
        }
        return Err(ProofError::TransactionProofInputsMismatch {
            index: 0,
            message: "native tx-leaf cache entry receipt mismatch".to_string(),
        });
    }

    note_receipt_arc_whir_leaf_verification();

    let canonical = canonical_receipt_from_tx_receipt(&artifact.receipt);
    let tx_view = tx_leaf_public_tx_from_consensus_tx(tx);
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
        receipt: artifact.receipt.clone(),
        binding,
        leaf: native_tx_leaf_record_from_artifact(&decoded),
    };
    NATIVE_TX_LEAF_VERIFY_CACHE
        .lock()
        .insert(artifact_hash, record.clone());
    Ok(record)
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

struct MergeRootP3Verifier;

impl ArtifactVerifier for MergeRootP3Verifier {
    fn kind(&self) -> ProofArtifactKind {
        ProofArtifactKind::MergeRoot
    }

    fn supports_verifier_profile(&self, verifier_profile: VerifierProfileDigest) -> bool {
        verifier_profile == legacy_block_artifact_verifier_profile(self.kind())
    }

    fn verify_block_artifact(
        &self,
        txs: &[crate::types::Transaction],
        _tx_artifacts: Option<&[TxValidityArtifact]>,
        expected_commitment: &[u8; 48],
        envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError> {
        if envelope.kind != self.kind() {
            return Err(ProofError::UnsupportedProofArtifact(format!(
                "expected {} block artifact, got {}",
                self.kind().label(),
                envelope.kind.label()
            )));
        }
        if envelope.verifier_profile != legacy_block_artifact_verifier_profile(self.kind()) {
            return Err(ProofError::AggregationProofInputsMismatch(
                "merge-root verifier profile mismatch".to_string(),
            ));
        }
        let verify_metrics = verify_aggregation_proof_safely(
            &envelope.artifact_bytes,
            txs.len(),
            expected_commitment,
        )?;
        Ok(BlockArtifactVerifyReport {
            tx_count: txs.len(),
            verified_statement_commitment: *expected_commitment,
            verify_ms: verify_metrics.total_ms,
            verify_batch_ms: verify_metrics.verify_batch_ms,
            cache_hit: Some(verify_metrics.cache_hit),
            cache_build_ms: Some(verify_metrics.cache_build_ms),
        })
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
        if envelope.kind != self.kind() {
            return Err(ProofError::UnsupportedProofArtifact(format!(
                "expected {} block artifact, got {}",
                self.kind().label(),
                envelope.kind.label()
            )));
        }
        if envelope.verifier_profile != experimental_native_receipt_root_verifier_profile() {
            return Err(ProofError::AggregationProofInputsMismatch(
                "receipt-root requires the native verifier profile".to_string(),
            ));
        }
        if envelope.artifact_bytes.len() > max_native_receipt_root_artifact_bytes(txs.len()) {
            return Err(ProofError::AggregationProofInputsMismatch(format!(
                "native receipt-root artifact size {} exceeds {} for tx_count {}",
                envelope.artifact_bytes.len(),
                max_native_receipt_root_artifact_bytes(txs.len()),
                txs.len()
            )));
        }
        let artifacts = tx_artifacts.ok_or(ProofError::MissingTransactionProofs)?;
        if artifacts.len() != txs.len() {
            return Err(ProofError::TransactionProofCountMismatch {
                expected: txs.len(),
                observed: artifacts.len(),
            });
        }
        let tx_artifact_registry = VerifierRegistry::default();
        let verified_bindings =
            verify_tx_validity_artifacts(&tx_artifact_registry, txs, artifacts)?;
        let derived_statement_commitment = commitment_from_statement_bindings(&verified_bindings)?;
        if derived_statement_commitment != *expected_commitment {
            return Err(ProofError::AggregationProofInputsMismatch(
                "receipt-root statement commitment mismatch".to_string(),
            ));
        }
        let start_verify = Instant::now();
        let root_metadata =
            verify_experimental_native_receipt_root_artifact(artifacts, &envelope.artifact_bytes)
                .map_err(|err| {
                ProofError::AggregationProofVerification(format!(
                    "native receipt-root verification failed: {err}"
                ))
            })?;
        if root_metadata.leaf_count as usize != artifacts.len() {
            return Err(ProofError::AggregationProofInputsMismatch(
                "receipt-root verified leaf count mismatch".to_string(),
            ));
        }
        Ok(BlockArtifactVerifyReport {
            tx_count: txs.len(),
            verified_statement_commitment: *expected_commitment,
            verify_ms: start_verify.elapsed().as_millis(),
            verify_batch_ms: 0,
            cache_hit: None,
            cache_build_ms: None,
        })
    }
}

struct ReceiptAccumulationVerifier;

impl ArtifactVerifier for ReceiptAccumulationVerifier {
    fn kind(&self) -> ProofArtifactKind {
        experimental_receipt_accumulation_artifact_kind()
    }

    fn supports_verifier_profile(&self, verifier_profile: VerifierProfileDigest) -> bool {
        verifier_profile == experimental_receipt_accumulation_verifier_profile()
    }

    fn verify_block_artifact(
        &self,
        txs: &[crate::types::Transaction],
        tx_artifacts: Option<&[TxValidityArtifact]>,
        expected_commitment: &[u8; 48],
        envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError> {
        if envelope.kind != self.kind() {
            return Err(ProofError::UnsupportedProofArtifact(format!(
                "expected {} block artifact, got {}",
                self.kind().label(),
                envelope.kind.label()
            )));
        }
        if envelope.verifier_profile != experimental_receipt_accumulation_verifier_profile() {
            return Err(ProofError::AggregationProofInputsMismatch(
                "receipt accumulation requires the accumulation verifier profile".to_string(),
            ));
        }
        if envelope.artifact_bytes.len() > max_receipt_accumulation_artifact_bytes(txs.len()) {
            return Err(ProofError::AggregationProofInputsMismatch(format!(
                "receipt accumulation artifact size {} exceeds {} for tx_count {}",
                envelope.artifact_bytes.len(),
                max_receipt_accumulation_artifact_bytes(txs.len()),
                txs.len()
            )));
        }
        let artifacts = tx_artifacts.ok_or(ProofError::MissingTransactionProofs)?;
        let receipts = artifacts
            .iter()
            .map(|artifact| artifact.receipt.clone())
            .collect::<Vec<_>>();
        verify_experimental_native_receipt_accumulation_artifact(
            txs,
            &receipts,
            Some(artifacts),
            expected_commitment,
            &envelope.artifact_bytes,
        )
    }
}

struct ReceiptArcWhirVerifier;

impl ArtifactVerifier for ReceiptArcWhirVerifier {
    fn kind(&self) -> ProofArtifactKind {
        experimental_receipt_arc_whir_artifact_kind()
    }

    fn supports_verifier_profile(&self, verifier_profile: VerifierProfileDigest) -> bool {
        verifier_profile == experimental_receipt_arc_whir_verifier_profile()
    }

    fn verify_block_artifact(
        &self,
        txs: &[crate::types::Transaction],
        tx_artifacts: Option<&[TxValidityArtifact]>,
        expected_commitment: &[u8; 48],
        envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError> {
        let artifacts = tx_artifacts.ok_or(ProofError::MissingTransactionProofs)?;
        let details = verify_receipt_arc_whir_native_artifacts_detailed(
            txs,
            artifacts,
            expected_commitment,
            envelope,
        )?;
        if details.residual_report.used_old_aggregation_backend {
            return Err(ProofError::AggregationProofInputsMismatch(
                "receipt_arc_whir touched the old aggregation backend".to_string(),
            ));
        }
        Ok(details.block_report)
    }
}

fn verify_receipt_arc_whir_native_artifacts_detailed(
    txs: &[crate::types::Transaction],
    tx_artifacts: &[TxValidityArtifact],
    expected_commitment: &[u8; 48],
    envelope: &ProofEnvelope,
) -> Result<ReceiptArcWhirVerifyDetails, ProofError> {
    if tx_artifacts.len() != txs.len() {
        return Err(ProofError::TransactionProofCountMismatch {
            expected: txs.len(),
            observed: tx_artifacts.len(),
        });
    }

    let start_verify = Instant::now();
    let (residual_report, execution_trace) = with_receipt_arc_whir_execution_trace(|| {
        let mut verified_bindings = Vec::with_capacity(txs.len());
        let mut receipts = Vec::with_capacity(txs.len());
        for (index, (tx, artifact)) in txs.iter().zip(tx_artifacts).enumerate() {
            let record = verify_native_tx_leaf_artifact_record(tx, artifact, None)
                .map_err(|err| reindex_tx_artifact_error(index, err))?;
            verified_bindings.push(record.binding);
            receipts.push(record.receipt);
        }

        let derived_statement_commitment = commitment_from_statement_bindings(&verified_bindings)?;
        if derived_statement_commitment != *expected_commitment {
            return Err(ProofError::AggregationProofInputsMismatch(
                "receipt_arc_whir statement commitment mismatch".to_string(),
            ));
        }

        verify_receipt_arc_whir_artifact_from_receipts(&receipts, expected_commitment, envelope)
    })?;

    Ok(ReceiptArcWhirVerifyDetails {
        block_report: BlockArtifactVerifyReport {
            tx_count: txs.len(),
            verified_statement_commitment: *expected_commitment,
            verify_ms: start_verify.elapsed().as_millis(),
            verify_batch_ms: 0,
            cache_hit: None,
            cache_build_ms: None,
        },
        residual_report: ReceiptArcWhirResidualReport {
            row_count: residual_report.row_count,
            artifact_bytes: residual_report.artifact_bytes,
            replayed_leaf_verifications: execution_trace.replayed_leaf_verifications,
            used_old_aggregation_backend: execution_trace.used_old_aggregation_backend,
        },
    })
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
    let public_inputs_digest =
        transaction_public_inputs_digest(proof).map_err(|err| err.to_string())?;
    Ok(TxValidityReceipt {
        statement_hash: transaction_statement_hash(proof),
        proof_digest: transaction_proof_digest(proof),
        public_inputs_digest,
        verifier_profile: transaction_verifier_profile_digest(proof),
    })
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

pub fn experimental_receipt_root_verifier_profile() -> VerifierProfileDigest {
    superneo_hegemon::experimental_receipt_root_verifier_profile()
}

pub fn experimental_tx_leaf_verifier_profile() -> VerifierProfileDigest {
    superneo_hegemon::experimental_tx_leaf_verifier_profile()
}

pub fn experimental_native_tx_leaf_verifier_profile() -> VerifierProfileDigest {
    native_tx_leaf_profile()
}

pub fn experimental_native_receipt_root_verifier_profile() -> VerifierProfileDigest {
    native_receipt_root_profile()
}

pub fn experimental_receipt_arc_whir_artifact_kind() -> ProofArtifactKind {
    receipt_arc_whir_kind()
}

pub fn experimental_receipt_arc_whir_verifier_profile() -> VerifierProfileDigest {
    receipt_arc_whir_profile()
}

pub fn experimental_receipt_accumulation_artifact_kind() -> ProofArtifactKind {
    ProofArtifactKind::Custom(RECEIPT_ACCUMULATION_ARTIFACT_KIND_BYTES)
}

pub fn experimental_receipt_accumulation_verifier_profile() -> VerifierProfileDigest {
    let mut material = Vec::new();
    material.extend_from_slice(b"hegemon.native.receipt-accumulation-profile.v1");
    material.extend_from_slice(&RECEIPT_ACCUMULATION_ARTIFACT_KIND_BYTES);
    material.extend_from_slice(&experimental_native_receipt_root_verifier_profile());
    blake3_384(&material)
}

struct NativeReceiptAccumulation;

impl ReceiptAccumulator for NativeReceiptAccumulation {
    fn kind(&self) -> ProofArtifactKind {
        experimental_receipt_accumulation_artifact_kind()
    }

    fn verifier_profile(&self) -> VerifierProfileDigest {
        experimental_receipt_accumulation_verifier_profile()
    }

    fn build(
        &self,
        receipts: &[TxValidityReceipt],
        artifacts: &[TxValidityArtifact],
    ) -> Result<ProofEnvelope, ProofError> {
        if receipts.len() != artifacts.len() {
            return Err(ProofError::TransactionProofCountMismatch {
                expected: receipts.len(),
                observed: artifacts.len(),
            });
        }
        for (index, (receipt, artifact)) in receipts.iter().zip(artifacts).enumerate() {
            if *receipt != artifact.receipt {
                return Err(ProofError::TransactionProofInputsMismatch {
                    index,
                    message: "receipt accumulation receipt mismatch".to_string(),
                });
            }
        }
        let built_root = build_experimental_native_receipt_root_artifact(artifacts)?;
        let artifact_hashes = artifacts
            .iter()
            .enumerate()
            .map(|(index, artifact)| native_receipt_accumulation_leaf_hash(index, artifact))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProofEnvelope {
            kind: self.kind(),
            verifier_profile: self.verifier_profile(),
            artifact_bytes: encode_receipt_accumulation_artifact(&ReceiptAccumulationArtifact {
                root_artifact_bytes: built_root.artifact_bytes,
                artifact_hashes,
            }),
        })
    }

    fn verify(
        &self,
        receipts: &[TxValidityReceipt],
        expected_commitment: &[u8; 48],
        envelope: &ProofEnvelope,
    ) -> Result<BlockArtifactVerifyReport, ProofError> {
        if envelope.kind != self.kind() {
            return Err(ProofError::UnsupportedProofArtifact(format!(
                "expected {} block artifact, got {}",
                self.kind().label(),
                envelope.kind.label()
            )));
        }
        if envelope.verifier_profile != self.verifier_profile() {
            return Err(ProofError::AggregationProofInputsMismatch(
                "receipt accumulation verifier profile mismatch".to_string(),
            ));
        }

        let artifact = decode_receipt_accumulation_artifact(&envelope.artifact_bytes)?;
        if artifact.artifact_hashes.len() != receipts.len() {
            return Err(ProofError::AggregationProofInputsMismatch(format!(
                "receipt accumulation artifact hash count {} does not match receipt count {}",
                artifact.artifact_hashes.len(),
                receipts.len()
            )));
        }

        let derived_commitment = commitment_from_receipts(receipts)?;
        if derived_commitment != *expected_commitment {
            return Err(ProofError::AggregationProofInputsMismatch(
                "receipt accumulation statement commitment mismatch".to_string(),
            ));
        }

        let mut records = Vec::with_capacity(receipts.len());
        for (index, (receipt, artifact_hash)) in
            receipts.iter().zip(&artifact.artifact_hashes).enumerate()
        {
            let Some(record) = NATIVE_TX_LEAF_VERIFY_CACHE.lock().get(*artifact_hash) else {
                return Err(ProofError::VerifiedTxArtifactUnavailable {
                    index,
                    message: format!(
                        "verified native tx-leaf store miss for artifact hash 0x{}",
                        hex::encode(artifact_hash)
                    ),
                });
            };
            if record.receipt != *receipt {
                return Err(ProofError::AggregationProofInputsMismatch(format!(
                    "receipt accumulation store entry mismatch at index {index}"
                )));
            }
            records.push(record.leaf);
        }

        let start_verify = Instant::now();
        let _metadata = verify_native_tx_leaf_receipt_root_artifact_from_records(
            &records,
            &artifact.root_artifact_bytes,
        )
        .map_err(|err| {
            ProofError::AggregationProofVerification(format!(
                "receipt accumulation verification failed: {err}"
            ))
        })?;
        Ok(BlockArtifactVerifyReport {
            tx_count: receipts.len(),
            verified_statement_commitment: *expected_commitment,
            verify_ms: start_verify.elapsed().as_millis(),
            verify_batch_ms: 0,
            cache_hit: Some(true),
            cache_build_ms: Some(0),
        })
    }
}

fn native_receipt_accumulation_leaf_hash(
    index: usize,
    artifact: &TxValidityArtifact,
) -> Result<[u8; 48], ProofError> {
    let envelope = artifact
        .proof
        .as_ref()
        .ok_or(ProofError::MissingTransactionProofs)?;
    if envelope.kind != ProofArtifactKind::TxLeaf
        || envelope.verifier_profile != experimental_native_tx_leaf_verifier_profile()
    {
        return Err(ProofError::TransactionProofInputsMismatch {
            index,
            message: "receipt accumulation requires native tx-leaf artifacts".to_string(),
        });
    }
    Ok(native_tx_leaf_artifact_hash(&envelope.artifact_bytes))
}

fn encode_receipt_accumulation_artifact(artifact: &ReceiptAccumulationArtifact) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        2 + 4 + 4 + artifact.root_artifact_bytes.len() + artifact.artifact_hashes.len() * 48,
    );
    bytes.extend_from_slice(&RECEIPT_ACCUMULATION_ARTIFACT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(artifact.root_artifact_bytes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(artifact.artifact_hashes.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&artifact.root_artifact_bytes);
    for artifact_hash in &artifact.artifact_hashes {
        bytes.extend_from_slice(artifact_hash);
    }
    bytes
}

fn decode_receipt_accumulation_artifact(
    bytes: &[u8],
) -> Result<ReceiptAccumulationArtifact, ProofError> {
    let mut cursor = 0usize;
    let version = read_u16(bytes, &mut cursor, "receipt accumulation artifact")?;
    if version != RECEIPT_ACCUMULATION_ARTIFACT_VERSION {
        return Err(ProofError::AggregationProofInputsMismatch(format!(
            "unsupported receipt accumulation artifact version {version}"
        )));
    }
    let root_len = read_u32(bytes, &mut cursor, "receipt accumulation artifact")? as usize;
    let hash_count = read_u32(bytes, &mut cursor, "receipt accumulation artifact")? as usize;
    let root_artifact_bytes = read_bytes(
        bytes,
        &mut cursor,
        root_len,
        "receipt accumulation artifact",
    )?;
    let mut artifact_hashes = Vec::with_capacity(hash_count);
    for _ in 0..hash_count {
        artifact_hashes.push(read_array(
            bytes,
            &mut cursor,
            "receipt accumulation artifact",
        )?);
    }
    if cursor != bytes.len() {
        return Err(ProofError::AggregationProofInputsMismatch(format!(
            "receipt accumulation artifact has {} trailing bytes",
            bytes.len().saturating_sub(cursor)
        )));
    }
    Ok(ReceiptAccumulationArtifact {
        root_artifact_bytes,
        artifact_hashes,
    })
}

fn max_receipt_accumulation_artifact_bytes(tx_count: usize) -> usize {
    2 + 4 + 4 + max_native_receipt_root_artifact_bytes(tx_count) + (tx_count * 48)
}

pub fn build_experimental_receipt_arc_whir_artifact(
    receipts: &[TxValidityReceipt],
) -> Result<ExperimentalReceiptRootArtifact, ProofError> {
    let envelope = build_receipt_arc_whir_artifact_from_receipts(receipts)?;
    Ok(ExperimentalReceiptRootArtifact {
        artifact_bytes: envelope.artifact_bytes,
        metadata: receipt_arc_whir_metadata(receipts.len()),
    })
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

pub fn build_experimental_native_receipt_accumulation_artifact(
    tx_artifacts: &[TxValidityArtifact],
) -> Result<ExperimentalReceiptRootArtifact, ProofError> {
    let built_root = build_experimental_native_receipt_root_artifact(tx_artifacts)?;
    let artifact_hashes = tx_artifacts
        .iter()
        .enumerate()
        .map(|(index, artifact)| native_receipt_accumulation_leaf_hash(index, artifact))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ExperimentalReceiptRootArtifact {
        artifact_bytes: encode_receipt_accumulation_artifact(&ReceiptAccumulationArtifact {
            root_artifact_bytes: built_root.artifact_bytes,
            artifact_hashes,
        }),
        metadata: built_root.metadata,
    })
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

pub fn verify_experimental_receipt_arc_whir_artifact(
    transactions: &[crate::types::Transaction],
    tx_artifacts: &[TxValidityArtifact],
    expected_commitment: &[u8; 48],
    envelope: &ProofEnvelope,
) -> Result<BlockArtifactVerifyReport, ProofError> {
    verify_receipt_arc_whir_native_artifacts_detailed(
        transactions,
        tx_artifacts,
        expected_commitment,
        envelope,
    )
    .map(|details| details.block_report)
}

pub fn verify_experimental_receipt_arc_whir_artifact_detailed(
    transactions: &[crate::types::Transaction],
    tx_artifacts: &[TxValidityArtifact],
    expected_commitment: &[u8; 48],
    envelope: &ProofEnvelope,
) -> Result<ReceiptArcWhirVerifyDetails, ProofError> {
    verify_receipt_arc_whir_native_artifacts_detailed(
        transactions,
        tx_artifacts,
        expected_commitment,
        envelope,
    )
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

pub fn verify_experimental_native_receipt_accumulation_artifact(
    transactions: &[crate::types::Transaction],
    receipts: &[TxValidityReceipt],
    tx_artifacts: Option<&[TxValidityArtifact]>,
    expected_commitment: &[u8; 48],
    artifact_bytes: &[u8],
) -> Result<BlockArtifactVerifyReport, ProofError> {
    if transactions.len() != receipts.len() {
        return Err(ProofError::TransactionProofCountMismatch {
            expected: transactions.len(),
            observed: receipts.len(),
        });
    }

    let receipt_artifacts_storage;
    let receipt_artifacts = if let Some(artifacts) = tx_artifacts {
        if artifacts.len() != receipts.len() {
            return Err(ProofError::TransactionProofCountMismatch {
                expected: receipts.len(),
                observed: artifacts.len(),
            });
        }
        artifacts
    } else {
        receipt_artifacts_storage = receipts
            .iter()
            .cloned()
            .map(tx_validity_artifact_from_receipt)
            .collect::<Vec<_>>();
        receipt_artifacts_storage.as_slice()
    };

    let envelope = ProofEnvelope {
        kind: experimental_receipt_accumulation_artifact_kind(),
        verifier_profile: experimental_receipt_accumulation_verifier_profile(),
        artifact_bytes: artifact_bytes.to_vec(),
    };
    let accumulation = decode_receipt_accumulation_artifact(artifact_bytes)?;
    if receipt_artifacts.len() != accumulation.artifact_hashes.len() {
        return Err(ProofError::TransactionProofCountMismatch {
            expected: accumulation.artifact_hashes.len(),
            observed: receipt_artifacts.len(),
        });
    }
    for (index, ((tx, artifact), expected_hash)) in transactions
        .iter()
        .zip(receipt_artifacts)
        .zip(&accumulation.artifact_hashes)
        .enumerate()
    {
        if artifact.proof.is_some() {
            verify_native_tx_leaf_artifact_record(tx, artifact, Some(*expected_hash))
                .map_err(|err| reindex_tx_artifact_error(index, err))?;
        }
    }
    NativeReceiptAccumulation.verify(receipts, expected_commitment, &envelope)
}

fn canonical_receipts_from_tx_receipts(
    receipts: &[TxValidityReceipt],
) -> Vec<CanonicalTxValidityReceipt> {
    receipts
        .iter()
        .map(canonical_receipt_from_tx_receipt)
        .collect()
}

fn canonical_receipt_from_tx_receipt(receipt: &TxValidityReceipt) -> CanonicalTxValidityReceipt {
    CanonicalTxValidityReceipt {
        statement_hash: receipt.statement_hash,
        proof_digest: receipt.proof_digest,
        public_inputs_digest: receipt.public_inputs_digest,
        verifier_profile: receipt.verifier_profile,
    }
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
    bincode::deserialize(&envelope.artifact_bytes).map_err(|err| {
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
    if tx.nullifiers.len() > MAX_INPUTS {
        return Err(format!(
            "transaction nullifier length {} exceeds MAX_INPUTS {MAX_INPUTS}",
            tx.nullifiers.len()
        ));
    }
    if tx.commitments.len() > MAX_OUTPUTS {
        return Err(format!(
            "transaction commitment length {} exceeds MAX_OUTPUTS {MAX_OUTPUTS}",
            tx.commitments.len()
        ));
    }
    if tx.ciphertext_hashes.len() > MAX_OUTPUTS {
        return Err(format!(
            "transaction ciphertext hash length {} exceeds MAX_OUTPUTS {MAX_OUTPUTS}",
            tx.ciphertext_hashes.len()
        ));
    }
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

    let mut message = Vec::new();
    message.extend_from_slice(transaction_circuit::proof::TX_STATEMENT_HASH_DOMAIN);
    message.extend_from_slice(&stark_inputs.merkle_root);
    for nf in &tx.nullifiers {
        message.extend_from_slice(nf);
    }
    for _ in tx.nullifiers.len()..MAX_INPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }
    for cm in &tx.commitments {
        message.extend_from_slice(cm);
    }
    for _ in tx.commitments.len()..MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }
    for ct in &tx.ciphertext_hashes {
        message.extend_from_slice(ct);
    }
    for _ in tx.ciphertext_hashes.len()..MAX_OUTPUTS {
        message.extend_from_slice(&[0u8; 48]);
    }
    message.extend_from_slice(&stark_inputs.fee.to_le_bytes());
    message.extend_from_slice(&value_balance.to_le_bytes());
    message.extend_from_slice(&tx.balance_tag);
    message.extend_from_slice(&tx.version.circuit.to_le_bytes());
    message.extend_from_slice(&tx.version.crypto.to_le_bytes());
    message.push(stark_inputs.stablecoin_enabled);
    message.extend_from_slice(&stark_inputs.stablecoin_asset_id.to_le_bytes());
    message.extend_from_slice(&stark_inputs.stablecoin_policy_hash);
    message.extend_from_slice(&stark_inputs.stablecoin_oracle_commitment);
    message.extend_from_slice(&stark_inputs.stablecoin_attestation_commitment);
    message.extend_from_slice(&stablecoin_issuance.to_le_bytes());
    message.extend_from_slice(&stark_inputs.stablecoin_policy_version.to_le_bytes());
    Ok(blake3_384(&message))
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
) -> Result<Vec<TxStatementBinding>, ProofError> {
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
                .map_err(|err| reindex_tx_artifact_error(index, err))
        })
        .collect()
}

fn verify_batch_proof_bytes_safely(
    proof_bytes: &[u8],
    batch_public_inputs: &BatchPublicInputs,
    start: usize,
    end: usize,
) -> Result<(), ProofError> {
    run_verifier(
        format!("flat batch STARK verification at tx range [{start}, {end})"),
        || verify_batch_proof_bytes(proof_bytes, batch_public_inputs),
        |err| {
            ProofError::AggregationProofVerification(format!(
                "flat batch STARK verification failed at tx range [{start}, {end}): {err}"
            ))
        },
    )
}

fn warm_aggregation_cache_safely(
    proof_bytes: &[u8],
    tx_count: usize,
    expected_commitment: &[u8; 48],
) -> Result<crate::aggregation::AggregationCacheWarmup, ProofError> {
    run_verifier(
        format!("aggregation cache prewarm for {tx_count} txs"),
        || warm_aggregation_cache_from_proof_bytes(proof_bytes, tx_count, expected_commitment),
        |err| {
            ProofError::AggregationProofVerification(format!(
                "aggregation cache prewarm failed: {err}"
            ))
        },
    )
}

fn verify_aggregation_proof_safely(
    proof_bytes: &[u8],
    tx_count: usize,
    expected_commitment: &[u8; 48],
) -> Result<crate::aggregation::AggregationVerifyMetrics, ProofError> {
    note_receipt_arc_whir_old_aggregation_backend();
    run_verifier(
        format!("aggregation proof verification for {tx_count} txs"),
        || verify_aggregation_proof_with_metrics(proof_bytes, tx_count, expected_commitment),
        |err| {
            ProofError::AggregationProofVerification(format!(
                "aggregation proof verification failed: {err}"
            ))
        },
    )
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

#[derive(Clone)]
pub struct ParallelProofVerifier {
    verifying_key: transaction_circuit::keys::VerifyingKey,
    verifier_registry: VerifierRegistry,
}

impl ParallelProofVerifier {
    pub fn new() -> Self {
        let (_, verifying_key) = generate_keys();
        Self {
            verifying_key,
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
            if block.proven_batch.is_some()
                || block.tx_validity_artifacts.is_some()
                || block.block_artifact.is_some()
            {
                return Err(ProofError::CommitmentProofEmptyBlock);
            }
            return apply_commitments(parent_commitment_tree, &block.transactions);
        }

        let verification_mode = block.proof_verification_mode;
        let tx_validity_artifacts = block.tx_validity_artifacts.as_ref();
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
        if matches!(verification_mode, ProofVerificationMode::InlineRequired)
            && tx_validity_artifacts.is_none()
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

            let tx_artifacts = tx_validity_artifacts.ok_or(ProofError::MissingTransactionProofs)?;
            let start_tx = Instant::now();
            let bindings = verify_tx_validity_artifacts(
                &self.verifier_registry,
                &block.transactions,
                tx_artifacts,
            )?;
            let tx_verify_ms = start_tx.elapsed().as_millis();

            let expected_tree = apply_commitments(parent_commitment_tree, &block.transactions)?;
            let anchors: Vec<[u8; 48]> = bindings.iter().map(|binding| binding.anchor).collect();
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

        let mut verified_tx_bindings: Option<Vec<TxStatementBinding>> = None;
        let resolved_statement_bindings = if let Some(bindings) =
            block.tx_statement_bindings.clone()
        {
            if bindings.len() != block.transactions.len() {
                return Err(ProofError::CommitmentProofInputsMismatch(format!(
                    "transaction statement binding count mismatch (expected {}, got {})",
                    block.transactions.len(),
                    bindings.len()
                )));
            }
            Some(bindings)
        } else if matches!(verification_mode, ProofVerificationMode::InlineRequired) {
            let artifacts = tx_validity_artifacts.ok_or(ProofError::MissingTransactionProofs)?;
            let bindings = verify_tx_validity_artifacts(
                &self.verifier_registry,
                &block.transactions,
                artifacts,
            )?;
            verified_tx_bindings = Some(bindings.clone());
            Some(bindings)
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

        let mut tx_verify_ms = 0u128;
        let mut aggregation_cache_hit = None;
        let mut aggregation_cache_build_ms = None;
        let mut aggregation_cache_prewarm_hit = None;
        let mut aggregation_cache_prewarm_build_ms = None;
        let mut aggregation_cache_prewarm_total_ms = None;
        let block_artifact = block
            .block_artifact
            .clone()
            .or_else(|| match proven_batch.mode {
                ProvenBatchMode::MergeRoot => {
                    proven_batch
                        .merge_root
                        .as_ref()
                        .map(|merge_root| ProofEnvelope {
                            kind: proven_batch.proof_kind,
                            verifier_profile: proven_batch.verifier_profile,
                            artifact_bytes: merge_root.root_proof.clone(),
                        })
                }
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
                ProvenBatchMode::InlineTx | ProvenBatchMode::FlatBatches => None,
            });

        let synthesized_receipt_artifacts;
        let (aggregation_verified, aggregation_verify_ms, aggregation_verify_batch_ms) =
            match proven_batch.mode {
                ProvenBatchMode::InlineTx => (false, 0u128, 0u128),
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
                    let expected_leaf_count = statement_hashes
                        .len()
                        .div_ceil(merge_root_leaf_fan_in_from_env())
                        as u32;
                    if merge_root.metadata.leaf_count != expected_leaf_count {
                        return Err(ProofError::ProvenBatchBindingMismatch(format!(
                            "merge-root leaf_count mismatch (payload {}, expected {})",
                            merge_root.metadata.leaf_count, expected_leaf_count
                        )));
                    }
                    let expected_tree_levels = merge_root_tree_levels_for_tx_count(tx_count);
                    if merge_root.metadata.tree_levels != expected_tree_levels {
                        return Err(ProofError::ProvenBatchBindingMismatch(format!(
                            "merge-root tree_levels mismatch (payload {}, expected {})",
                            merge_root.metadata.tree_levels, expected_tree_levels
                        )));
                    }
                    let expected_leaf_manifest =
                        merge_root_leaf_manifest_commitment(&statement_hashes)
                            .map_err(ProofError::AggregationProofInputsMismatch)?;
                    if merge_root.metadata.leaf_manifest_commitment != expected_leaf_manifest {
                        return Err(ProofError::ProvenBatchBindingMismatch(
                            "merge-root leaf_manifest_commitment mismatch".to_string(),
                        ));
                    }
                    if merge_root.root_proof.is_empty() {
                        return Err(ProofError::MissingAggregationProofForSelfContainedMode);
                    }

                    let prewarm_start = Instant::now();
                    match warm_aggregation_cache_safely(
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

                    let merge_root_verifier = self
                        .verifier_registry
                        .resolve(proven_batch.proof_kind, proven_batch.verifier_profile)?;
                    let verify_report = merge_root_verifier.verify_block_artifact(
                        &block.transactions,
                        tx_validity_artifacts.map(|artifacts| artifacts.as_slice()),
                        &expected_commitment,
                        block_artifact
                            .as_ref()
                            .ok_or(ProofError::MissingAggregationProofForSelfContainedMode)?,
                    )?;
                    aggregation_cache_hit = verify_report.cache_hit;
                    aggregation_cache_build_ms = verify_report.cache_build_ms;
                    (true, verify_report.verify_ms, verify_report.verify_batch_ms)
                }
                ProvenBatchMode::ReceiptRoot => {
                    let receipt_root = proven_batch.receipt_root.as_ref().ok_or_else(|| {
                        ProofError::ProvenBatchBindingMismatch(
                            "missing receipt_root payload for ReceiptRoot mode".to_string(),
                        )
                    })?;
                    if receipt_root.metadata.leaf_count != tx_count as u32 {
                        return Err(ProofError::ProvenBatchBindingMismatch(format!(
                            "receipt-root leaf_count mismatch (payload {}, expected {})",
                            receipt_root.metadata.leaf_count, tx_count
                        )));
                    }
                    if receipt_root.receipts.len() != tx_count {
                        return Err(ProofError::ProvenBatchBindingMismatch(format!(
                            "receipt-root receipt count mismatch (payload {}, expected {})",
                            receipt_root.receipts.len(),
                            tx_count
                        )));
                    }
                    let artifacts = if let Some(artifacts) = tx_validity_artifacts {
                        artifacts.as_slice()
                    } else if proof_kind_uses_receipt_only_tx_artifacts(proven_batch.proof_kind) {
                        synthesized_receipt_artifacts = receipt_root
                            .receipts
                            .iter()
                            .cloned()
                            .map(tx_validity_artifact_from_receipt)
                            .collect::<Vec<_>>();
                        synthesized_receipt_artifacts.as_slice()
                    } else {
                        return Err(ProofError::MissingTransactionProofs);
                    };
                    let artifact_receipts = artifacts
                        .iter()
                        .map(|artifact| artifact.receipt.clone())
                        .collect::<Vec<_>>();
                    if receipt_root.receipts != artifact_receipts {
                        return Err(ProofError::ProvenBatchBindingMismatch(
                            "receipt-root payload receipts do not match tx validity artifacts"
                                .to_string(),
                        ));
                    }
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
                    (true, verify_report.verify_ms, verify_report.verify_batch_ms)
                }
            };

        if !aggregation_verified {
            match verification_mode {
                ProofVerificationMode::InlineRequired => {
                    if verified_tx_bindings.is_none() {
                        let artifacts =
                            tx_validity_artifacts.ok_or(ProofError::MissingTransactionProofs)?;
                        let start_tx = Instant::now();
                        verified_tx_bindings = Some(verify_tx_validity_artifacts(
                            &self.verifier_registry,
                            &block.transactions,
                            artifacts,
                        )?);
                        tx_verify_ms = start_tx.elapsed().as_millis();
                    }
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
            let bindings = verified_tx_bindings
                .as_ref()
                .ok_or(ProofError::MissingTransactionProofs)?;
            let anchors: Vec<[u8; 48]> = bindings.iter().map(|binding| binding.anchor).collect();
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

fn proof_kind_uses_receipt_only_tx_artifacts(kind: ProofArtifactKind) -> bool {
    kind == experimental_receipt_accumulation_artifact_kind()
}

fn read_u16(bytes: &[u8], cursor: &mut usize, context: &str) -> Result<u16, ProofError> {
    Ok(u16::from_le_bytes(read_array::<2>(bytes, cursor, context)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize, context: &str) -> Result<u32, ProofError> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, cursor, context)?))
}

fn read_bytes(
    bytes: &[u8],
    cursor: &mut usize,
    len: usize,
    context: &str,
) -> Result<Vec<u8>, ProofError> {
    if bytes.len().saturating_sub(*cursor) < len {
        return Err(ProofError::AggregationProofInputsMismatch(format!(
            "{context} ended early while reading {len} bytes"
        )));
    }
    let out = bytes[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(out)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
    context: &str,
) -> Result<[u8; N], ProofError> {
    if bytes.len().saturating_sub(*cursor) < N {
        return Err(ProofError::AggregationProofInputsMismatch(format!(
            "{context} ended early while reading {N} bytes"
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cursor..*cursor + N]);
    *cursor += N;
    Ok(out)
}

fn total_batch_proof_payload_bytes(batch: &crate::types::ProvenBatch) -> usize {
    match batch.mode {
        ProvenBatchMode::InlineTx => 0,
        ProvenBatchMode::FlatBatches => {
            batch.flat_batches.iter().map(|item| item.proof.len()).sum()
        }
        ProvenBatchMode::MergeRoot => batch
            .merge_root
            .as_ref()
            .map(|merge| merge.root_proof.len())
            .unwrap_or(0),
        ProvenBatchMode::ReceiptRoot => batch
            .receipt_root
            .as_ref()
            .map(|receipt_root| receipt_root.root_proof.len())
            .unwrap_or(0),
    }
}

fn total_batch_proof_uncompressed_bytes(batch: &crate::types::ProvenBatch) -> usize {
    match batch.mode {
        ProvenBatchMode::InlineTx => 0,
        ProvenBatchMode::FlatBatches => {
            batch.flat_batches.iter().map(|item| item.proof.len()).sum()
        }
        ProvenBatchMode::MergeRoot => batch
            .merge_root
            .as_ref()
            .map(|merge| aggregation_proof_uncompressed_len(&merge.root_proof))
            .unwrap_or(0),
        ProvenBatchMode::ReceiptRoot => batch
            .receipt_root
            .as_ref()
            .map(|receipt_root| receipt_root.root_proof.len())
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

        let binding_subset = &statement_bindings[start..end];
        let tx_subset = &transactions[start..end];
        let payload = decode_flat_batch_proof_bytes(&item.proof)?;
        match payload.proof_kind {
            FLAT_BATCH_PROOF_KIND_P3_BATCH_STARK => {
                let batch_public_inputs = decode_batch_public_inputs(&payload.batch_public_values)?;
                if batch_public_inputs.batch_size as usize != (end - start) {
                    return Err(ProofError::FlatBatchCoverage(format!(
                        "flat batch public input tx_count mismatch: expected {}, got {}",
                        end - start,
                        batch_public_inputs.batch_size
                    )));
                }

                verify_flat_batch_public_inputs_binding(
                    &batch_public_inputs,
                    binding_subset,
                    start,
                    end,
                )?;
                verify_batch_proof_bytes_safely(
                    &payload.batch_proof,
                    &batch_public_inputs,
                    start,
                    end,
                )?;
                verify_flat_batch_bindings_against_transactions(
                    &batch_public_inputs,
                    tx_subset,
                    start,
                    end,
                )?;
            }
            FLAT_BATCH_PROOF_KIND_TX_PROOF_MANIFEST => {
                return Err(ProofError::FlatBatchProofDecodeFailed(
                    "tx-proof-manifest flat batches were removed after the local lane benchmark showed raw tx-proof shipping wins".to_string(),
                ));
            }
            unsupported => {
                return Err(ProofError::FlatBatchProofDecodeFailed(format!(
                    "unsupported flat batch proof kind {unsupported}"
                )));
            }
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

#[cfg(test)]
fn verify_tx_proof_manifest_public_inputs_binding(
    batch_public_inputs: &TxProofManifestPublicInputs,
    bindings: &[TxStatementBinding],
    start: usize,
    end: usize,
) -> Result<(), ProofError> {
    let expected_fee = bindings.iter().fold(0u128, |acc, binding| {
        acc.saturating_add(u128::from(binding.fee))
    });
    if expected_fee > u64::MAX as u128 {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "tx-proof-manifest total fee overflows u64 in tx range [{start}, {end})"
        )));
    }
    if batch_public_inputs.total_fee != expected_fee as u64 {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "tx-proof-manifest total fee mismatch in tx range [{start}, {end})"
        )));
    }

    let expected_circuit_version = bindings.first().map(|binding| binding.circuit_version);
    if bindings
        .iter()
        .any(|binding| Some(binding.circuit_version) != expected_circuit_version)
    {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "tx-proof-manifest statement bindings contain mixed circuit versions in tx range [{start}, {end})"
        )));
    }
    if batch_public_inputs.circuit_version != expected_circuit_version.unwrap_or(0) {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "tx-proof-manifest circuit version mismatch in tx range [{start}, {end})"
        )));
    }

    let expected_statement_hashes: Vec<[u8; 48]> = bindings
        .iter()
        .map(|binding| binding.statement_hash)
        .collect();
    if batch_public_inputs.statement_hashes != expected_statement_hashes {
        return Err(ProofError::ProvenBatchBindingMismatch(format!(
            "tx-proof-manifest statement hash mismatch in tx range [{start}, {end})"
        )));
    }

    Ok(())
}

fn verify_flat_batch_bindings_against_transactions(
    batch_public_inputs: &BatchPublicInputs,
    transactions: &[crate::types::Transaction],
    start: usize,
    end: usize,
) -> Result<(), ProofError> {
    let expected_nullifiers = padded_nullifiers_from_transactions(transactions);
    let expected_commitments = padded_commitments_from_transactions(transactions);
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

    Ok(())
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
    use tx_proof_manifest::TxProofManifestPublicInputs;

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

    fn tx_proof_manifest_inputs(
        statement_hash: [u8; 48],
        fee: u64,
        circuit_version: u32,
    ) -> TxProofManifestPublicInputs {
        TxProofManifestPublicInputs {
            batch_size: 1,
            statement_hashes: vec![statement_hash],
            nullifiers: vec![[0u8; 48]; MAX_INPUTS],
            commitments: vec![[0u8; 48]; MAX_OUTPUTS],
            total_fee: fee,
            circuit_version,
        }
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

    #[test]
    fn tx_proof_manifest_binding_rejects_statement_hash_mismatch() {
        let inputs = tx_proof_manifest_inputs([1u8; 48], 10, 1);
        let bindings = vec![binding([9u8; 48], 10, 1)];
        let err = verify_tx_proof_manifest_public_inputs_binding(&inputs, &bindings, 0, 1)
            .expect_err("statement hash mismatch should fail");
        assert!(matches!(err, ProofError::ProvenBatchBindingMismatch(_)));
    }

    #[test]
    fn tx_proof_manifest_binding_rejects_fee_mismatch() {
        let inputs = tx_proof_manifest_inputs([5u8; 48], 11, 1);
        let bindings = vec![binding([1u8; 48], 10, 1)];
        let err = verify_tx_proof_manifest_public_inputs_binding(&inputs, &bindings, 0, 1)
            .expect_err("fee mismatch should fail");
        assert!(matches!(err, ProofError::ProvenBatchBindingMismatch(_)));
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
}
