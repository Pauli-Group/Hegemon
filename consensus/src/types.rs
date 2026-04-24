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
    let mut hasher = Sha384::new();
    hasher.update(version.circuit.to_le_bytes());
    hasher.update(version.crypto.to_le_bytes());
    for nf in nullifiers {
        hasher.update(nf);
    }
    for cm in commitments {
        hasher.update(cm);
    }
    for ct_hash in ciphertext_hashes {
        hasher.update(ct_hash);
    }
    hasher.update(balance_tag);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&sha256(digest.as_slice()));
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofVerificationMode {
    InlineRequired,
    SelfContainedAggregation,
}

impl Default for ProofVerificationMode {
    fn default() -> Self {
        Self::InlineRequired
    }
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
}
