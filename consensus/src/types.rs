use crate::backend_interface::CommitmentBlockProof;
use crypto::hashes::{blake3_384, sha256};
use protocol_versioning::{VersionBinding, VersionMatrix};
use sha2::{Digest, Sha384};
pub use state_da::{
    DaChunk, DaChunkProof, DaEncoding, DaError, DaMultiChunkProof, DaMultiEncoding, DaParams,
    DaRoot,
};
use transaction_circuit::hashing_pq::ciphertext_hash_bytes;

pub type Nullifier = [u8; 48];
pub type Commitment = [u8; 48];
pub type BalanceTag = [u8; 48];
pub type FeeCommitment = [u8; 48];
pub type ValidatorSetCommitment = [u8; 48];
pub type BlockHash = [u8; 32];
pub type ValidatorId = [u8; 32];
pub type StarkCommitment = [u8; 48];
pub type VersionCommitment = [u8; 48];
pub type StateRoot = [u8; 48];
pub type NullifierRoot = [u8; 48];
pub type VerifierProfileDigest = [u8; 48];
pub type SupplyDigest = u128;
pub type Amount = u64;
pub const BLOCK_PROOF_FORMAT_ID_V5: u8 = 5;
pub const STAGE1_SHIELDED_POOL_FAMILY_ID: u16 = 1;

pub fn kernel_root_from_shielded_root(root: &StateRoot) -> StateRoot {
    let mut bytes = Vec::with_capacity(24 + 2 + 48);
    bytes.extend_from_slice(b"hegemon-kernel-root-v1");
    bytes.extend_from_slice(&STAGE1_SHIELDED_POOL_FAMILY_ID.to_le_bytes());
    bytes.extend_from_slice(root);
    blake3_384(&bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub id: BlockHash,
    pub nullifiers: Vec<Nullifier>,
    pub commitments: Vec<Commitment>,
    pub balance_tag: BalanceTag,
    pub version: VersionBinding,
    pub ciphertexts: Vec<Vec<u8>>,
    pub ciphertext_hashes: Vec<[u8; 48]>,
}

pub fn build_da_blob(transactions: &[Transaction]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&(transactions.len() as u32).to_le_bytes());
    for tx in transactions {
        blob.extend_from_slice(&(tx.ciphertexts.len() as u32).to_le_bytes());
        for ciphertext in &tx.ciphertexts {
            blob.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
            blob.extend_from_slice(ciphertext);
        }
    }
    blob
}

pub fn encode_da_blob(
    transactions: &[Transaction],
    params: DaParams,
) -> Result<DaEncoding, DaError> {
    state_da::encode_da_blob(&build_da_blob(transactions), params)
}

pub fn encode_da_blob_multipage(
    transactions: &[Transaction],
    params: DaParams,
) -> Result<DaMultiEncoding, DaError> {
    state_da::encode_da_blob_multipage(&build_da_blob(transactions), params)
}

pub fn da_root(transactions: &[Transaction], params: DaParams) -> Result<DaRoot, DaError> {
    state_da::da_root(&build_da_blob(transactions), params)
}

pub fn verify_da_chunk(root: DaRoot, proof: &DaChunkProof) -> Result<(), DaError> {
    state_da::verify_da_chunk(root, proof)
}

pub fn verify_da_multi_chunk(root: DaRoot, proof: &DaMultiChunkProof) -> Result<(), DaError> {
    state_da::verify_da_multi_chunk(root, proof)
}

impl Transaction {
    pub fn new(
        nullifiers: Vec<Nullifier>,
        commitments: Vec<Commitment>,
        balance_tag: BalanceTag,
        version: VersionBinding,
        ciphertexts: Vec<Vec<u8>>,
    ) -> Self {
        let ciphertext_hashes = ciphertexts
            .iter()
            .map(|ct| ciphertext_hash_bytes(ct))
            .collect::<Vec<_>>();
        let id = compute_transaction_id(
            &nullifiers,
            &commitments,
            &balance_tag,
            version,
            &ciphertext_hashes,
        );
        Self {
            id,
            nullifiers,
            commitments,
            balance_tag,
            version,
            ciphertexts,
            ciphertext_hashes,
        }
    }

    pub fn new_with_hashes(
        nullifiers: Vec<Nullifier>,
        commitments: Vec<Commitment>,
        balance_tag: BalanceTag,
        version: VersionBinding,
        ciphertext_hashes: Vec<[u8; 48]>,
    ) -> Self {
        let id = compute_transaction_id(
            &nullifiers,
            &commitments,
            &balance_tag,
            version,
            &ciphertext_hashes,
        );
        Self {
            id,
            nullifiers,
            commitments,
            balance_tag,
            version,
            ciphertexts: Vec::new(),
            ciphertext_hashes,
        }
    }

    pub fn hash(&self) -> BlockHash {
        compute_transaction_id(
            &self.nullifiers,
            &self.commitments,
            &self.balance_tag,
            self.version,
            &self.ciphertext_hashes,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoinbaseSource {
    TransactionIndex(usize),
    BalanceTag(BalanceTag),
}

impl CoinbaseSource {
    pub fn balance_tag(&self, transactions: &[Transaction]) -> Option<BalanceTag> {
        match self {
            CoinbaseSource::TransactionIndex(idx) => {
                transactions.get(*idx).map(|tx| tx.balance_tag)
            }
            CoinbaseSource::BalanceTag(tag) => Some(*tag),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseData {
    pub minted: Amount,
    pub fees: i64,
    pub burns: Amount,
    pub source: CoinbaseSource,
}

impl CoinbaseData {
    pub fn balance_tag(&self, transactions: &[Transaction]) -> Option<BalanceTag> {
        self.source.balance_tag(transactions)
    }

    pub fn net_native_delta(&self) -> i128 {
        self.minted as i128 + self.fees as i128 - self.burns as i128
    }
}

fn compute_transaction_id(
    nullifiers: &[Nullifier],
    commitments: &[Commitment],
    balance_tag: &BalanceTag,
    version: VersionBinding,
    ciphertext_hashes: &[[u8; 48]],
) -> BlockHash {
    let preimage = transaction_hash_preimage(
        nullifiers,
        commitments,
        balance_tag,
        version,
        ciphertext_hashes,
    );
    let mut hasher = Sha384::new();
    hasher.update(preimage);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&sha256(digest.as_slice()));
    out
}

pub fn transaction_hash_preimage(
    nullifiers: &[Nullifier],
    commitments: &[Commitment],
    balance_tag: &BalanceTag,
    version: VersionBinding,
    ciphertext_hashes: &[[u8; 48]],
) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(
        4 + (nullifiers.len() + commitments.len() + ciphertext_hashes.len() + 1) * 48,
    );
    preimage.extend_from_slice(&version.circuit.to_le_bytes());
    preimage.extend_from_slice(&version.crypto.to_le_bytes());
    for nf in nullifiers {
        preimage.extend_from_slice(nf);
    }
    for cm in commitments {
        preimage.extend_from_slice(cm);
    }
    for ct_hash in ciphertext_hashes {
        preimage.extend_from_slice(ct_hash);
    }
    preimage.extend_from_slice(balance_tag);
    preimage
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ProofVerificationMode {
    #[default]
    InlineRequired,
    SelfContainedAggregation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProofArtifactKind {
    InlineTx,
    TxLeaf,
    ReceiptRoot,
    RecursiveBlockV1,
    RecursiveBlockV2,
    Custom([u8; 16]),
}

impl ProofArtifactKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::InlineTx => "inline_tx",
            Self::TxLeaf => "tx_leaf",
            Self::ReceiptRoot => "receipt_root",
            Self::RecursiveBlockV1 => "recursive_block_v1",
            Self::RecursiveBlockV2 => "recursive_block_v2",
            Self::Custom(_) => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArtifactRoute {
    pub mode: ProvenBatchMode,
    pub kind: ProofArtifactKind,
}

impl ArtifactRoute {
    pub const fn new(mode: ProvenBatchMode, kind: ProofArtifactKind) -> Self {
        Self { mode, kind }
    }

    pub fn from_mode(mode: ProvenBatchMode) -> Self {
        Self::new(mode, proof_artifact_kind_from_mode(mode))
    }

    pub const fn shipped_recursive_block_v2() -> Self {
        Self::new(
            ProvenBatchMode::RecursiveBlock,
            ProofArtifactKind::RecursiveBlockV2,
        )
    }

    pub const fn explicit_receipt_root() -> Self {
        Self::new(ProvenBatchMode::ReceiptRoot, ProofArtifactKind::ReceiptRoot)
    }

    pub fn is_compatible_with_mode(self) -> bool {
        match self.mode {
            ProvenBatchMode::InlineTx => self.kind == ProofArtifactKind::InlineTx,
            ProvenBatchMode::ReceiptRoot => self.kind == ProofArtifactKind::ReceiptRoot,
            ProvenBatchMode::RecursiveBlock => matches!(
                self.kind,
                ProofArtifactKind::RecursiveBlockV1 | ProofArtifactKind::RecursiveBlockV2
            ),
        }
    }

    pub fn is_shipped(self) -> bool {
        self.mode == ProvenBatchMode::RecursiveBlock
            && self.kind == ProofArtifactKind::RecursiveBlockV2
    }

    pub fn is_experimental(self) -> bool {
        self.mode == ProvenBatchMode::ReceiptRoot && self.kind == ProofArtifactKind::ReceiptRoot
    }
}

pub fn proof_artifact_kind_from_mode(mode: ProvenBatchMode) -> ProofArtifactKind {
    match mode {
        ProvenBatchMode::InlineTx => ProofArtifactKind::InlineTx,
        ProvenBatchMode::ReceiptRoot => ProofArtifactKind::ReceiptRoot,
        ProvenBatchMode::RecursiveBlock => ProofArtifactKind::RecursiveBlockV2,
    }
}

pub fn legacy_block_artifact_verifier_profile(kind: ProofArtifactKind) -> VerifierProfileDigest {
    let mut material = Vec::new();
    material.extend_from_slice(b"hegemon.legacy-block-artifact-profile.v1");
    material.extend_from_slice(kind.label().as_bytes());
    material.extend_from_slice(&BLOCK_PROOF_FORMAT_ID_V5.to_le_bytes());
    blake3_384(&material)
}

pub fn canonical_shipped_artifact_route() -> ArtifactRoute {
    ArtifactRoute::shipped_recursive_block_v2()
}

pub fn canonical_experimental_artifact_route() -> ArtifactRoute {
    ArtifactRoute::explicit_receipt_root()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofEnvelope {
    pub kind: ProofArtifactKind,
    pub verifier_profile: VerifierProfileDigest,
    pub artifact_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxValidityReceipt {
    pub statement_hash: [u8; 48],
    pub proof_digest: [u8; 48],
    pub public_inputs_digest: [u8; 48],
    pub verifier_profile: VerifierProfileDigest,
}

impl TxValidityReceipt {
    pub const fn new(
        statement_hash: [u8; 48],
        proof_digest: [u8; 48],
        public_inputs_digest: [u8; 48],
        verifier_profile: VerifierProfileDigest,
    ) -> Self {
        Self {
            statement_hash,
            proof_digest,
            public_inputs_digest,
            verifier_profile,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxValidityArtifact {
    pub receipt: TxValidityReceipt,
    pub proof: Option<ProofEnvelope>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxValidityClaim {
    pub receipt: TxValidityReceipt,
    pub binding: TxStatementBinding,
}

impl TxValidityClaim {
    pub fn new(receipt: TxValidityReceipt, binding: TxStatementBinding) -> Self {
        Self { receipt, binding }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProvenBatchMode {
    InlineTx,
    ReceiptRoot,
    RecursiveBlock,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRootMetadata {
    pub params_fingerprint: [u8; 48],
    pub relation_id: [u8; 32],
    pub shape_digest: [u8; 32],
    pub leaf_count: u32,
    pub fold_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRootProofPayload {
    pub root_proof: Vec<u8>,
    pub metadata: ReceiptRootMetadata,
    pub receipts: Vec<TxValidityReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenBatch {
    pub version: u8,
    pub tx_count: u32,
    pub tx_statements_commitment: [u8; 48],
    pub da_root: DaRoot,
    pub da_chunk_count: u32,
    pub commitment_proof: CommitmentBlockProof,
    pub mode: ProvenBatchMode,
    pub proof_kind: ProofArtifactKind,
    pub verifier_profile: VerifierProfileDigest,
    pub receipt_root: Option<ReceiptRootProofPayload>,
}

impl ProvenBatch {
    pub fn route(&self) -> ArtifactRoute {
        ArtifactRoute::new(self.mode, self.proof_kind)
    }

    pub fn uses_route(&self, route: ArtifactRoute) -> bool {
        self.mode == route.mode && self.proof_kind == route.kind
    }
}

/// Parent-agnostic proof object over an exact ordered transaction set.
///
/// The current fresh-testnet implementation reuses the existing self-contained
/// aggregation payload shape while the node and operator surfaces migrate to
/// the new artifact-market naming.
pub type CandidateArtifact = ProvenBatch;

/// Public metadata that lets builders discover and compare reusable candidate
/// artifacts without downloading the full payload immediately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactAnnouncement {
    pub artifact_hash: [u8; 32],
    pub tx_statements_commitment: [u8; 48],
    pub tx_count: u32,
    pub proof_mode: ProvenBatchMode,
    pub proof_kind: ProofArtifactKind,
    pub verifier_profile: VerifierProfileDigest,
}

impl ArtifactAnnouncement {
    pub fn route(&self) -> ArtifactRoute {
        ArtifactRoute::new(self.proof_mode, self.proof_kind)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxStatementBinding {
    pub statement_hash: [u8; 48],
    pub anchor: [u8; 48],
    pub fee: u64,
    pub circuit_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block<BH> {
    pub header: BH,
    pub transactions: Vec<Transaction>,
    pub coinbase: Option<CoinbaseData>,
    pub proven_batch: Option<ProvenBatch>,
    /// Block-level aggregation artifact envelope in the canonical route
    /// selected by `proven_batch`.
    pub block_artifact: Option<ProofEnvelope>,
    /// Canonical per-transaction claims in transaction order. Each claim pairs
    /// the tx-validity receipt with the canonical statement binding that the
    /// rest of the product stack uses to build `tx_statements_commitment`.
    pub tx_validity_claims: Option<Vec<TxValidityClaim>>,
    /// Optional commitment to transaction statement hashes, derived by the caller in canonical
    /// transaction order (for example from binding-hash statements on node imports).
    pub tx_statements_commitment: Option<[u8; 48]>,
    pub proof_verification_mode: ProofVerificationMode,
}

impl<BH> Block<BH> {
    pub fn map_header<T>(self, header: T) -> Block<T> {
        Block {
            header,
            transactions: self.transactions,
            coinbase: self.coinbase,
            proven_batch: self.proven_batch,
            block_artifact: self.block_artifact,
            tx_validity_claims: self.tx_validity_claims,
            tx_statements_commitment: self.tx_statements_commitment,
            proof_verification_mode: self.proof_verification_mode,
        }
    }
}

pub type ConsensusBlock = Block<crate::header::BlockHeader>;

pub fn compute_fee_commitment(transactions: &[Transaction]) -> FeeCommitment {
    let mut tags: Vec<BalanceTag> = transactions.iter().map(|tx| tx.balance_tag).collect();
    tags.sort_unstable();
    let mut data = Vec::with_capacity(tags.len() * 48);
    for tag in tags {
        data.extend_from_slice(&tag);
    }
    blake3_384(&data)
}

pub fn compute_proof_commitment(transactions: &[Transaction]) -> StarkCommitment {
    let mut hasher = Sha384::new();
    for tx in transactions {
        hasher.update(tx.hash());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 48];
    out.copy_from_slice(&digest);
    out
}

pub fn compute_version_matrix(transactions: &[Transaction]) -> VersionMatrix {
    let mut matrix = VersionMatrix::new();
    for tx in transactions {
        matrix.observe(tx.version);
    }
    matrix
}

pub fn compute_version_commitment(transactions: &[Transaction]) -> VersionCommitment {
    let matrix = compute_version_matrix(transactions);
    matrix.commitment()
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol_versioning::DEFAULT_VERSION_BINDING;
    use serde::Deserialize;
    use std::collections::BTreeSet;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanDaRootVectorFile {
        schema_version: u32,
        da_blob_cases: Vec<LeanDaBlobCase>,
        da_leaf_preimage_cases: Vec<LeanDaLeafPreimageCase>,
        da_node_preimage_cases: Vec<LeanDaNodePreimageCase>,
        da_shard_count_cases: Vec<LeanDaShardCountCase>,
        da_proof_path_len_cases: Vec<LeanDaProofPathLenCase>,
        da_merkle_step_cases: Vec<LeanDaMerkleStepCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanDaBlobCase {
        name: String,
        ciphertexts_hex: Vec<Vec<String>>,
        expected_blob_hex: String,
        expected_blob_len: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanDaLeafPreimageCase {
        name: String,
        index: u32,
        data_hex: String,
        expected_preimage_hex: String,
        expected_preimage_len: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanDaNodePreimageCase {
        name: String,
        left_hex: String,
        right_hex: String,
        expected_preimage_hex: String,
        expected_preimage_len: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanDaShardCountCase {
        name: String,
        blob_len: usize,
        chunk_size: u32,
        sample_count: u32,
        expected_valid: bool,
        expected_data_shards: u64,
        expected_parity_shards: u64,
        expected_total_shards: usize,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanDaProofPathLenCase {
        name: String,
        kind: String,
        path_len: usize,
        expected_valid: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanDaMerkleStepCase {
        name: String,
        node_index: u32,
        current_hex: String,
        sibling_hex: String,
        expected_preimage_hex: String,
        expected_preimage_len: usize,
    }

    #[test]
    fn lean_generated_da_root_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_DA_ROOT_VECTORS") else {
            eprintln!("HEGEMON_LEAN_DA_ROOT_VECTORS not set; skipping generated Lean vector check");
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean DA-root vectors");
        let vectors: LeanDaRootVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean DA-root vectors");
        assert_eq!(vectors.schema_version, 1);

        let mut names = BTreeSet::new();
        for case in &vectors.da_blob_cases {
            assert!(names.insert(case.name.clone()));
            let transactions = case
                .ciphertexts_hex
                .iter()
                .map(|tx_ciphertexts| {
                    let ciphertexts = tx_ciphertexts
                        .iter()
                        .map(|value| decode_hex_vec(value))
                        .collect::<Vec<_>>();
                    Transaction::new(
                        Vec::new(),
                        Vec::new(),
                        [0u8; 48],
                        DEFAULT_VERSION_BINDING,
                        ciphertexts,
                    )
                })
                .collect::<Vec<_>>();
            let actual_blob = build_da_blob(&transactions);
            assert_eq!(
                actual_blob,
                decode_hex_vec(&case.expected_blob_hex),
                "{} DA blob bytes drifted from Lean spec",
                case.name
            );
            assert_eq!(
                actual_blob.len(),
                case.expected_blob_len,
                "{} DA blob length drifted from Lean spec",
                case.name
            );
        }

        for case in &vectors.da_leaf_preimage_cases {
            assert!(names.insert(case.name.clone()));
            let data = decode_hex_vec(&case.data_hex);
            let actual_preimage = state_da::da_leaf_preimage(case.index, &data);
            assert_eq!(
                actual_preimage,
                decode_hex_vec(&case.expected_preimage_hex),
                "{} DA leaf preimage drifted from Lean spec",
                case.name
            );
            assert_eq!(
                actual_preimage.len(),
                case.expected_preimage_len,
                "{} DA leaf preimage length drifted from Lean spec",
                case.name
            );
        }

        for case in &vectors.da_node_preimage_cases {
            assert!(names.insert(case.name.clone()));
            let left = decode_fixed_hex::<48>(&case.left_hex);
            let right = decode_fixed_hex::<48>(&case.right_hex);
            let actual_preimage = state_da::da_node_preimage(&left, &right);
            assert_eq!(
                actual_preimage.as_slice(),
                decode_hex_vec(&case.expected_preimage_hex).as_slice(),
                "{} DA node preimage drifted from Lean spec",
                case.name
            );
            assert_eq!(
                actual_preimage.len(),
                case.expected_preimage_len,
                "{} DA node preimage length drifted from Lean spec",
                case.name
            );
        }

        for case in &vectors.da_shard_count_cases {
            assert!(names.insert(case.name.clone()));
            let params = DaParams {
                chunk_size: case.chunk_size,
                sample_count: case.sample_count,
            };
            let blob = vec![0u8; case.blob_len];
            let chunk_count = state_da::chunk_count_for_blob(case.blob_len, params);
            assert_eq!(
                chunk_count.is_ok(),
                case.expected_valid,
                "{} DA shard-count validity drifted from Lean spec: {chunk_count:?}",
                case.name
            );
            if case.expected_valid {
                let encoding = state_da::encode_da_blob(&blob, params)
                    .expect("valid Lean shard-count case must encode");
                assert_eq!(
                    encoding.data_shards(),
                    case.expected_data_shards,
                    "{} DA data-shard count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    encoding.parity_shards(),
                    case.expected_parity_shards,
                    "{} DA parity-shard count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    encoding.chunks().len(),
                    case.expected_total_shards,
                    "{} DA total-shard count drifted from Lean spec",
                    case.name
                );
                assert_eq!(
                    chunk_count.expect("valid chunk count"),
                    case.expected_total_shards,
                    "{} public DA chunk count drifted from Lean spec",
                    case.name
                );
            }
        }

        for case in &vectors.da_proof_path_len_cases {
            assert!(names.insert(case.name.clone()));
            let actual_valid = match case.kind.as_str() {
                "chunk" => state_da::da_chunk_merkle_path_len_is_admissible(case.path_len),
                "page" => state_da::da_page_merkle_path_len_is_admissible(case.path_len),
                other => panic!("{} unknown DA proof path kind {other}", case.name),
            };
            assert_eq!(
                actual_valid, case.expected_valid,
                "{} DA proof path length admission drifted from Lean spec",
                case.name
            );

            if !case.expected_valid {
                let page_root = crypto::hashes::blake3_384(&state_da::da_leaf_preimage(0, &[0]));
                let mut proof = state_da::DaChunkProof {
                    chunk: state_da::DaChunk {
                        index: 0,
                        data: vec![0u8; 1],
                    },
                    merkle_path: vec![[0u8; 48]; case.path_len],
                };
                let result = if case.kind == "chunk" {
                    state_da::verify_da_chunk([0u8; 48], &proof)
                } else {
                    proof.merkle_path.clear();
                    state_da::verify_da_multi_chunk(
                        [0u8; 48],
                        &state_da::DaMultiChunkProof {
                            page_index: 0,
                            page_root,
                            page_proof: proof,
                            page_merkle_path: vec![[0u8; 48]; case.path_len],
                        },
                    )
                };
                assert!(
                    matches!(result, Err(state_da::DaError::ProofPathTooLong { .. })),
                    "{} over-cap DA proof path did not fail closed before hash replay: {result:?}",
                    case.name
                );
            }
        }

        for case in &vectors.da_merkle_step_cases {
            assert!(names.insert(case.name.clone()));
            let current = decode_fixed_hex::<48>(&case.current_hex);
            let sibling = decode_fixed_hex::<48>(&case.sibling_hex);
            let actual_preimage =
                state_da::da_merkle_step_preimage(case.node_index, &current, &sibling);
            assert_eq!(
                actual_preimage.as_slice(),
                decode_hex_vec(&case.expected_preimage_hex).as_slice(),
                "{} DA Merkle step orientation drifted from Lean spec",
                case.name
            );
            assert_eq!(
                actual_preimage.len(),
                case.expected_preimage_len,
                "{} DA Merkle step preimage length drifted from Lean spec",
                case.name
            );
        }
    }

    #[test]
    fn transaction_id_is_deterministic() {
        let tx = Transaction::new(
            vec![[1u8; 48]],
            vec![[2u8; 48]],
            [3u8; 48],
            DEFAULT_VERSION_BINDING,
            vec![],
        );
        assert_eq!(tx.hash(), tx.id);
    }

    #[test]
    fn transaction_version_changes_hash() {
        let base_nullifiers = vec![[1u8; 48]];
        let base_commitments = vec![[2u8; 48]];
        let base_tag = [3u8; 48];
        let v1 = Transaction::new(
            base_nullifiers.clone(),
            base_commitments.clone(),
            base_tag,
            DEFAULT_VERSION_BINDING,
            vec![],
        );
        let upgraded_version = VersionBinding::new(
            DEFAULT_VERSION_BINDING.circuit.saturating_add(1),
            DEFAULT_VERSION_BINDING.crypto,
        );
        let v2 = Transaction::new(
            base_nullifiers,
            base_commitments,
            base_tag,
            upgraded_version,
            vec![],
        );
        assert_ne!(v1.id, v2.id);
    }

    #[test]
    fn fee_commitment_sorted() {
        let tx_a = Transaction::new(
            vec![[1u8; 48]],
            vec![],
            [3u8; 48],
            DEFAULT_VERSION_BINDING,
            vec![],
        );
        let tx_b = Transaction::new(
            vec![[2u8; 48]],
            vec![],
            [1u8; 48],
            DEFAULT_VERSION_BINDING,
            vec![],
        );
        let tag = compute_fee_commitment(&[tx_a.clone(), tx_b.clone()]);
        let tag_swapped = compute_fee_commitment(&[tx_b, tx_a]);
        assert_eq!(tag, tag_swapped);
    }

    #[test]
    fn proof_commitment_depends_on_transaction_order() {
        let tx_a = Transaction::new(
            vec![[1u8; 48]],
            vec![],
            [3u8; 48],
            DEFAULT_VERSION_BINDING,
            vec![],
        );
        let tx_b = Transaction::new(
            vec![[2u8; 48]],
            vec![],
            [4u8; 48],
            DEFAULT_VERSION_BINDING,
            vec![],
        );
        let commitment = compute_proof_commitment(&[tx_a.clone(), tx_b.clone()]);
        let commitment_swapped = compute_proof_commitment(&[tx_b, tx_a]);
        assert_ne!(commitment, commitment_swapped);
    }

    #[test]
    fn version_commitment_tracks_counts() {
        let tx_v1 = Transaction::new(
            vec![[1u8; 48]],
            vec![],
            [3u8; 48],
            DEFAULT_VERSION_BINDING,
            vec![],
        );
        let tx_v2 = Transaction::new(
            vec![[4u8; 48]],
            vec![],
            [5u8; 48],
            VersionBinding::new(
                DEFAULT_VERSION_BINDING.circuit.saturating_add(1),
                DEFAULT_VERSION_BINDING.crypto,
            ),
            vec![],
        );
        let matrix = compute_version_matrix(&[tx_v1.clone(), tx_v1.clone(), tx_v2.clone()]);
        let counts = matrix.counts();
        assert_eq!(counts.get(&DEFAULT_VERSION_BINDING), Some(&2));
        assert_eq!(counts.get(&tx_v2.version), Some(&1));
        let commitment = compute_version_commitment(&[tx_v1, tx_v2]);
        assert_ne!(commitment, [0u8; 48]);
    }

    #[test]
    fn canonical_artifact_routes_are_explicit() {
        assert_eq!(
            canonical_shipped_artifact_route(),
            ArtifactRoute::new(
                ProvenBatchMode::RecursiveBlock,
                ProofArtifactKind::RecursiveBlockV2
            )
        );
        assert_eq!(
            canonical_experimental_artifact_route(),
            ArtifactRoute::new(ProvenBatchMode::ReceiptRoot, ProofArtifactKind::ReceiptRoot)
        );
        assert!(canonical_shipped_artifact_route().is_shipped());
        assert!(canonical_experimental_artifact_route().is_experimental());
    }

    #[test]
    fn artifact_route_classification_distinguishes_legacy_and_shipped_paths() {
        let legacy_recursive = ArtifactRoute::new(
            ProvenBatchMode::RecursiveBlock,
            ProofArtifactKind::RecursiveBlockV1,
        );
        assert!(legacy_recursive.is_compatible_with_mode());
        assert!(!legacy_recursive.is_shipped());
        assert!(!legacy_recursive.is_experimental());

        let invalid_route = ArtifactRoute::new(
            ProvenBatchMode::ReceiptRoot,
            ProofArtifactKind::RecursiveBlockV2,
        );
        assert!(!invalid_route.is_compatible_with_mode());
    }

    fn decode_hex_vec(value: &str) -> Vec<u8> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        hex::decode(trimmed).expect("valid hex")
    }

    fn decode_fixed_hex<const N: usize>(value: &str) -> [u8; N] {
        let bytes = decode_hex_vec(value);
        bytes
            .try_into()
            .unwrap_or_else(|bytes: Vec<u8>| panic!("expected {N} hex bytes, got {}", bytes.len()))
    }
}
