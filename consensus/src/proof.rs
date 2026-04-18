use crate::commitment_tree::CommitmentTreeState;
use crate::error::ProofError;
use crate::types::{
    Block, DaParams, DaRoot, FeeCommitment, ProofArtifactKind, ProofEnvelope,
    ProofVerificationMode, ProvenBatchMode, ReceiptRootMetadata, StarkCommitment, StateRoot,
    TxStatementBinding, TxValidityArtifact, TxValidityClaim, TxValidityReceipt,
    VerifierProfileDigest, VersionCommitment, compute_fee_commitment,
    compute_proof_commitment, compute_version_commitment, da_root,
    kernel_root_from_shielded_root,
};
use block_circuit::{CommitmentBlockProof, CommitmentBlockProver, verify_block_commitment};
use block_recursion::{
    BlockLeafRecordV1, BlockSemanticInputsV1, deserialize_recursive_block_artifact_v1,
    deserialize_recursive_block_artifact_v2, public_replay_v1, public_replay_v2,
    recursive_block_artifact_verifier_profile_v1, recursive_block_artifact_verifier_profile_v2,
    verify_block_recursive_v1, verify_block_recursive_v2,
};
use crypto::hashes::blake3_384;
use parking_lot::Mutex;
use rayon::prelude::*;
use std::any::Any;
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
    verify_native_tx_leaf_receipt_root_artifact_from_records_with_params,
    verify_receipt_root_artifact_bytes, verify_tx_leaf_artifact_bytes,
    verify_verified_tx_proof_receipt_root_artifact_bytes,
};
use transaction_circuit::constants::{MAX_INPUTS, MAX_OUTPUTS};
use transaction_circuit::hashing_pq::{ciphertext_hash_bytes, felts_to_bytes48};
use transaction_circuit::keys::generate_keys;
use transaction_circuit::proof::{
    SerializedStarkInputs, TransactionProof, decode_transaction_proof_bytes_exact,
    transaction_proof_digest, transaction_public_inputs_digest,
    transaction_public_inputs_digest_from_serialized, transaction_statement_hash,
    transaction_verifier_profile_digest, transaction_verifier_profile_digest_for_version,
    verify as verify_transaction_proof,
};

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

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerifiedNativeTxLeaf {
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
            if envelope.verifier_profile != recursive_block_artifact_verifier_profile_v1() {
                return Err(ProofError::AggregationProofInputsMismatch(
                    "recursive_block_v1 requires the v1 verifier profile".to_string(),
                ));
            }
            let parsed = deserialize_recursive_block_artifact_v1(&envelope.artifact_bytes)
                .map_err(|err| {
                    ProofError::AggregationProofVerification(format!(
                        "recursive_block_v1 artifact decode failed: {err}"
                    ))
                })?;
            if parsed.public.tx_count as usize != txs.len() {
                return Err(ProofError::AggregationProofInputsMismatch(format!(
                    "recursive_block_v1 tx_count mismatch (payload {}, expected {})",
                    parsed.public.tx_count,
                    txs.len()
                )));
            }
            if parsed.public.tx_statements_commitment != *expected_commitment {
                return Err(ProofError::AggregationProofInputsMismatch(
                    "recursive_block_v1 statement commitment mismatch".to_string(),
                ));
            }
            let expected_public = public_replay_v1(&block_records, semantic).map_err(|err| {
                ProofError::AggregationProofVerification(format!(
                    "recursive_block_v1 public replay failed: {err}"
                ))
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
            if envelope.verifier_profile != recursive_block_artifact_verifier_profile_v2() {
                return Err(ProofError::AggregationProofInputsMismatch(
                    "recursive_block_v2 requires the v2 verifier profile".to_string(),
                ));
            }
            let parsed = deserialize_recursive_block_artifact_v2(&envelope.artifact_bytes)
                .map_err(|err| {
                    ProofError::AggregationProofVerification(format!(
                        "recursive_block_v2 artifact decode failed: {err}"
                    ))
                })?;
            if parsed.public.tx_count as usize != txs.len() {
                return Err(ProofError::AggregationProofInputsMismatch(format!(
                    "recursive_block_v2 tx_count mismatch (payload {}, expected {})",
                    parsed.public.tx_count,
                    txs.len()
                )));
            }
            if parsed.public.tx_statements_commitment != *expected_commitment {
                return Err(ProofError::AggregationProofInputsMismatch(
                    "recursive_block_v2 statement commitment mismatch".to_string(),
                ));
            }
            let expected_public = public_replay_v2(&block_records, semantic).map_err(|err| {
                ProofError::AggregationProofVerification(format!(
                    "recursive_block_v2 public replay failed: {err}"
                ))
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
        let verified_records = verify_native_tx_leaf_artifact_records(txs, artifacts)?;
        let verified_bindings = verified_records
            .iter()
            .map(|record| record.binding.clone())
            .collect::<Vec<_>>();
        let derived_statement_commitment = commitment_from_statement_bindings(&verified_bindings)?;
        if derived_statement_commitment != *expected_commitment {
            return Err(ProofError::AggregationProofInputsMismatch(
                "receipt-root statement commitment mismatch".to_string(),
            ));
        }
        let start_verify = Instant::now();
        let leaf_records = verified_records
            .iter()
            .map(|record| record.leaf.clone())
            .collect::<Vec<_>>();
        let verify_mode = load_native_receipt_root_verify_mode();
        let root_metadata = match verify_mode {
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
            root_verify_mode: Some(verify_mode.label()),
        })
    }
}

pub fn recursive_block_artifact_verifier_profile() -> VerifierProfileDigest {
    recursive_block_artifact_verifier_profile_v2()
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
                verifier_profile == recursive_block_artifact_verifier_profile_v1()
            }
            ProofArtifactKind::RecursiveBlockV2 => {
                verifier_profile == recursive_block_artifact_verifier_profile_v2()
            }
            _ => false,
        }
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
        match self.kind {
            ProofArtifactKind::RecursiveBlockV1 => {
                if envelope.verifier_profile != recursive_block_artifact_verifier_profile_v1() {
                    return Err(ProofError::AggregationProofInputsMismatch(
                        "recursive_block_v1 requires the v1 verifier profile".to_string(),
                    ));
                }
                let parsed = deserialize_recursive_block_artifact_v1(&envelope.artifact_bytes)
                    .map_err(|err| {
                        ProofError::AggregationProofVerification(format!(
                            "recursive_block_v1 artifact decode failed: {err}"
                        ))
                    })?;
                if parsed.artifact.header.artifact_version_rec
                    != block_recursion::RECURSIVE_BLOCK_ARTIFACT_VERSION_V1
                {
                    return Err(ProofError::AggregationProofInputsMismatch(format!(
                        "recursive_block_v1 header version mismatch: {}",
                        parsed.artifact.header.artifact_version_rec
                    )));
                }
                if parsed.public.tx_count as usize != txs.len() {
                    return Err(ProofError::AggregationProofInputsMismatch(format!(
                        "recursive_block_v1 tx_count mismatch (payload {}, expected {})",
                        parsed.public.tx_count,
                        txs.len()
                    )));
                }
                if parsed.public.tx_statements_commitment != *expected_commitment {
                    return Err(ProofError::AggregationProofInputsMismatch(
                        "recursive_block_v1 statement commitment mismatch".to_string(),
                    ));
                }
                verify_block_recursive_v1(&parsed, &parsed.public).map_err(|err| {
                    ProofError::AggregationProofVerification(format!(
                        "recursive_block_v1 verification failed: {err}"
                    ))
                })?;
            }
            ProofArtifactKind::RecursiveBlockV2 => {
                if envelope.verifier_profile != recursive_block_artifact_verifier_profile_v2() {
                    return Err(ProofError::AggregationProofInputsMismatch(
                        "recursive_block_v2 requires the v2 verifier profile".to_string(),
                    ));
                }
                let parsed = deserialize_recursive_block_artifact_v2(&envelope.artifact_bytes)
                    .map_err(|err| {
                        ProofError::AggregationProofVerification(format!(
                            "recursive_block_v2 artifact decode failed: {err}"
                        ))
                    })?;
                if parsed.artifact.header.artifact_version_rec
                    != block_recursion::RECURSIVE_BLOCK_ARTIFACT_VERSION_V2
                {
                    return Err(ProofError::AggregationProofInputsMismatch(format!(
                        "recursive_block_v2 header version mismatch: {}",
                        parsed.artifact.header.artifact_version_rec
                    )));
                }
                if parsed.public.tx_count as usize != txs.len() {
                    return Err(ProofError::AggregationProofInputsMismatch(format!(
                        "recursive_block_v2 tx_count mismatch (payload {}, expected {})",
                        parsed.public.tx_count,
                        txs.len()
                    )));
                }
                if parsed.public.tx_statements_commitment != *expected_commitment {
                    return Err(ProofError::AggregationProofInputsMismatch(
                        "recursive_block_v2 statement commitment mismatch".to_string(),
                    ));
                }
                verify_block_recursive_v2(&parsed, &parsed.public).map_err(|err| {
                    ProofError::AggregationProofVerification(format!(
                        "recursive_block_v2 verification failed: {err}"
                    ))
                })?;
            }
            _ => {
                return Err(ProofError::UnsupportedProofArtifact(format!(
                    "proof kind {} does not support recursive block verification",
                    self.kind.label()
                )));
            }
        }

        Ok(BlockArtifactVerifyReport {
            tx_count: txs.len(),
            verified_statement_commitment: *expected_commitment,
            verify_ms: 0,
            verify_batch_ms: 0,
            cache_hit: None,
            cache_build_ms: None,
            root_verify_mode: Some(self.kind().label()),
        })
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
    let public_inputs_digest =
        transaction_public_inputs_digest(proof).map_err(|err| err.to_string())?;
    let verifier_profile =
        transaction_verifier_profile_digest(proof).map_err(|err| err.to_string())?;
    Ok(TxValidityReceipt {
        statement_hash: transaction_statement_hash(proof),
        proof_digest: transaction_proof_digest(proof),
        public_inputs_digest,
        verifier_profile,
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

pub fn experimental_native_receipt_root_params_fingerprint() -> [u8; 48] {
    superneo_hegemon::native_backend_params().parameter_fingerprint()
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
        &superneo_hegemon::native_backend_params(),
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

pub fn tx_statement_bindings_from_tx_artifacts(
    transactions: &[crate::types::Transaction],
    artifacts: &[TxValidityArtifact],
) -> Result<Vec<TxStatementBinding>, ProofError> {
    tx_statement_bindings_from_claims(&tx_validity_claims_from_tx_artifacts(
        transactions,
        artifacts,
    )?)
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

        if block.transactions.is_empty() {
            if block.proven_batch.is_some()
                || backend_inputs
                    .and_then(BlockBackendInputs::tx_validity_artifacts)
                    .is_some()
                || block.tx_validity_claims.is_some()
                || block.block_artifact.is_some()
            {
                return Err(ProofError::CommitmentProofEmptyBlock);
            }
            return apply_commitments(parent_commitment_tree, &block.transactions);
        }

        let verification_mode = block.proof_verification_mode;
        let tx_validity_artifacts = backend_inputs.and_then(BlockBackendInputs::tx_validity_artifacts);
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
        let resolved_claims = if let Some(claims) = block.tx_validity_claims.clone() {
            if claims.len() != block.transactions.len() {
                return Err(ProofError::CommitmentProofInputsMismatch(format!(
                    "transaction claim count mismatch (expected {}, got {})",
                    block.transactions.len(),
                    claims.len()
                )));
            }
            Some(claims)
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
        let resolved_receipts = resolved_claims
            .as_deref()
            .map(tx_validity_receipts_from_claims);
        let derived_statement_commitment = resolved_statement_bindings
            .as_deref()
            .map(commitment_from_statement_bindings)
            .transpose()?;
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
                let claim_receipts = resolved_receipts
                    .as_ref()
                    .ok_or(ProofError::MissingTransactionValidityClaims)?;
                if receipt_root.receipts != *claim_receipts {
                    return Err(ProofError::ProvenBatchBindingMismatch(
                        "receipt-root payload receipts do not match tx validity claims"
                            .to_string(),
                    ));
                }
                let artifacts = tx_validity_artifacts
                    .ok_or(ProofError::MissingTransactionProofs)?;
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
                let artifacts = tx_validity_artifacts
                    .ok_or(ProofError::MissingTransactionProofs)?;
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
    use std::sync::Mutex as StdMutex;

    static TEST_ENV_LOCK: StdMutex<()> = StdMutex::new(());

    struct EnvGuard {
        previous_verify_mode: Option<String>,
        _guard: std::sync::MutexGuard<'static, ()>,
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

    fn sample_recursive_records(tx_count: u32) -> Vec<block_recursion::BlockLeafRecordV1> {
        (0..tx_count)
            .map(|tx_index| block_recursion::BlockLeafRecordV1 {
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

    fn sample_recursive_semantic() -> block_recursion::BlockSemanticInputsV1 {
        block_recursion::BlockSemanticInputsV1 {
            tx_statements_commitment: [0u8; 48],
            start_shielded_root: [3u8; 48],
            end_shielded_root: [4u8; 48],
            start_kernel_root: [5u8; 48],
            end_kernel_root: [6u8; 48],
            nullifier_root: [7u8; 48],
            da_root: [8u8; 48],
            start_tree_commitment: [9u8; 48],
            end_tree_commitment: [10u8; 48],
        }
    }

    fn sample_recursive_block_artifact_v1(
        tx_count: u32,
    ) -> block_recursion::RecursiveBlockArtifactV1 {
        let records = sample_recursive_records(tx_count);
        let semantic = sample_recursive_semantic();
        block_recursion::prove_block_recursive_v1(&block_recursion::BlockRecursiveProverInputV1 {
            records,
            semantic,
        })
        .expect("prove recursive_block_v1 artifact")
    }

    fn sample_recursive_block_artifact_v2(
        tx_count: u32,
    ) -> block_recursion::RecursiveBlockArtifactV2 {
        let records = sample_recursive_records(tx_count);
        let semantic = sample_recursive_semantic();
        block_recursion::prove_block_recursive_v2(&block_recursion::BlockRecursiveProverInputV2 {
            records,
            semantic,
        })
        .expect("prove recursive_block_v2 artifact")
    }

    #[test]
    #[ignore = "tree_v2 is experimental and not on the shipped product lane"]
    fn recursive_block_v2_verifier_is_registered_and_accepts_valid_artifact() {
        let registry = VerifierRegistry::default();
        let verifier_profile = recursive_block_artifact_verifier_profile_v2();
        let verifier = registry
            .resolve(ProofArtifactKind::RecursiveBlockV2, verifier_profile)
            .expect("recursive_block_v2 verifier registered");
        let artifact = sample_recursive_block_artifact_v2(1);
        let bytes = block_recursion::serialize_recursive_block_artifact_v2(&artifact)
            .expect("serialize recursive_block_v2 artifact");
        let envelope = ProofEnvelope {
            kind: ProofArtifactKind::RecursiveBlockV2,
            verifier_profile,
            artifact_bytes: bytes,
        };
        let report = verifier
            .verify_block_artifact(&[tx_with_commitments(vec![])], None, &[0u8; 48], &envelope)
            .expect("recursive_block_v2 verifier should accept a structurally valid artifact");
        assert_eq!(report.tx_count, 1);
    }

    #[test]
    fn recursive_block_v1_verifier_is_registered_and_accepts_valid_artifact() {
        let registry = VerifierRegistry::default();
        let verifier_profile = recursive_block_artifact_verifier_profile_v1();
        let verifier = registry
            .resolve(ProofArtifactKind::RecursiveBlockV1, verifier_profile)
            .expect("recursive_block_v1 verifier registered");
        let artifact = sample_recursive_block_artifact_v1(1);
        let bytes = block_recursion::serialize_recursive_block_artifact_v1(&artifact)
            .expect("serialize recursive_block_v1 artifact");
        let envelope = ProofEnvelope {
            kind: ProofArtifactKind::RecursiveBlockV1,
            verifier_profile,
            artifact_bytes: bytes,
        };
        let report = verifier
            .verify_block_artifact(&[tx_with_commitments(vec![])], None, &[0u8; 48], &envelope)
            .expect("recursive verifier should accept a structurally valid artifact");
        assert_eq!(report.tx_count, 1);
    }

    #[test]
    fn recursive_block_v1_verifier_rejects_tx_count_mismatch() {
        let verifier = RecursiveBlockVerifier {
            kind: ProofArtifactKind::RecursiveBlockV1,
        };
        let artifact = sample_recursive_block_artifact_v1(1);
        let bytes = block_recursion::serialize_recursive_block_artifact_v1(&artifact)
            .expect("serialize recursive artifact");
        let envelope = ProofEnvelope {
            kind: ProofArtifactKind::RecursiveBlockV1,
            verifier_profile: recursive_block_artifact_verifier_profile_v1(),
            artifact_bytes: bytes,
        };
        let err = verifier
            .verify_block_artifact(&[], None, &[0u8; 48], &envelope)
            .expect_err("tx_count mismatch");
        assert!(matches!(err, ProofError::AggregationProofInputsMismatch(_)));
    }

    #[test]
    #[ignore = "tree_v2 is experimental and not on the shipped product lane"]
    fn recursive_block_v2_verifier_rejects_tx_count_mismatch() {
        let verifier = RecursiveBlockVerifier {
            kind: ProofArtifactKind::RecursiveBlockV2,
        };
        let artifact = sample_recursive_block_artifact_v2(1);
        let bytes = block_recursion::serialize_recursive_block_artifact_v2(&artifact)
            .expect("serialize recursive_block_v2 artifact");
        let envelope = ProofEnvelope {
            kind: ProofArtifactKind::RecursiveBlockV2,
            verifier_profile: recursive_block_artifact_verifier_profile_v2(),
            artifact_bytes: bytes,
        };
        let err = verifier
            .verify_block_artifact(&[], None, &[0u8; 48], &envelope)
            .expect_err("tx_count mismatch");
        assert!(matches!(err, ProofError::AggregationProofInputsMismatch(_)));
    }
}
