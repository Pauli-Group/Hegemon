use block_circuit::CommitmentBlockProof;
use crypto::hashes::{blake3_384, sha256};
use protocol_versioning::{VersionBinding, VersionMatrix};
use sha2::{Digest, Sha384};
pub use state_da::{
    DaChunk, DaChunkProof, DaEncoding, DaError, DaMultiChunkProof, DaMultiEncoding, DaParams,
    DaRoot,
};
use transaction_circuit::{hashing_pq::ciphertext_hash_bytes, TransactionProof};

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
pub type SupplyDigest = u128;
pub type Amount = u64;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block<BH> {
    pub header: BH,
    pub transactions: Vec<Transaction>,
    pub coinbase: Option<CoinbaseData>,
    pub commitment_proof: Option<CommitmentBlockProof>,
    pub aggregation_proof: Option<Vec<u8>>,
    pub transaction_proofs: Option<Vec<TransactionProof>>,
}

impl<BH> Block<BH> {
    pub fn map_header<T>(self, header: T) -> Block<T> {
        Block {
            header,
            transactions: self.transactions,
            coinbase: self.coinbase,
            commitment_proof: self.commitment_proof,
            aggregation_proof: self.aggregation_proof,
            transaction_proofs: self.transaction_proofs,
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
}
